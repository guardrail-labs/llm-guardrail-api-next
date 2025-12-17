from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from fastapi import (
    APIRouter,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from app.services.audit import emit_audit_event
from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.llm_client import get_client
from app.services.policy import (
    _normalize_family,
    current_rules_version,
    sanitize_text,
)
from app.services.threat_feed import apply_dynamic_redactions, threat_feed_enabled
from app.services.verifier import content_fingerprint
from app.services.verifier.reuse_cache import (
    ENABLED as REUSE_ENABLED,
    get as reuse_get,
    make_key as reuse_key,
)
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.shared.request_meta import get_client_meta
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
    inc_egress_family,
    inc_ingress_family,
    inc_redaction,
    inc_verifier_reuse,
)

router = APIRouter(prefix="/v1", tags=["openai-compat"])


# ---------------------------
# Health
# ---------------------------


@router.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "provider": os.environ.get("LLM_PROVIDER") or "local-echo",
        "policy_version": current_rules_version(),
    }


# ---------------------------
# Models (subset for compat)
# ---------------------------


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


def _apply_sanitized_text_to_messages(
    messages: List[ChatMessage], sanitized_text: str
) -> List[ChatMessage]:
    """
    Apply sanitized text back onto a list of ChatMessage objects.

    The sanitized_text is expected to be a plaintext transcript with lines of the form:
        "<role>: <content...>"
    where <content> may span multiple subsequent lines until the next "<role>:" marker.

    We preserve full multiline content for each message and only update when content differs.
    """
    if not messages:
        return messages
    if not sanitized_text or not sanitized_text.strip():
        return messages

    # Known roles we expect in OpenAI-style chat; keep lowercase for matching.
    KNOWN_ROLES = {"system", "user", "assistant", "tool", "function"}

    lines = sanitized_text.splitlines()

    # Parse sanitized transcript into an ordered list of (role, text) blocks,
    # where each block's text may span multiple lines.
    blocks: List[tuple[str, str]] = []
    current_role: Optional[str] = None
    current_buf: List[str] = []

    def _flush() -> None:
        nonlocal blocks, current_role, current_buf
        if current_role is not None:
            # Strip one trailing newline but keep internal newlines intact
            blocks.append((current_role, "\n".join(current_buf)))
        current_role = None
        current_buf = []

    for raw in lines:
        # Detect a new role marker at the start of the line: "<role>:"
        # We match only known roles to avoid false positives like "Note: ..."
        marker_role: Optional[str] = None
        remainder: Optional[str] = None
        if ":" in raw:
            head, tail = raw.split(":", 1)
            r = head.strip().lower()
            if r in KNOWN_ROLES:
                marker_role = r
                remainder = tail.lstrip()

        if marker_role is not None:
            # Starting a new block; flush the previous one
            _flush()
            current_role = marker_role
            current_buf = [remainder or ""]
        else:
            # Continuation of the current block (if any)
            if current_role is None:
                # No active block yet; ignore leading noise until a valid role marker appears
                continue
            current_buf.append(raw)

    _flush()

    if not blocks:
        # Nothing to apply; keep original messages
        return messages

    # Build per-role queues so we can apply sanitized blocks in-order to the original roles
    from collections import defaultdict, deque

    role_queues: Dict[str, deque[str]] = defaultdict(deque)
    for role, text in blocks:
        role_queues[role].append(text)

    changed = False
    applied: List[ChatMessage] = []

    for original in messages:
        role_key = (original.role or "").lower()
        if role_key in role_queues and role_queues[role_key]:
            new_text = role_queues[role_key].popleft()
            if new_text != original.content:
                changed = True
                applied.append(original.model_copy(update={"content": new_text}))
            else:
                applied.append(original)
        else:
            applied.append(original)

    return applied if changed else messages


def _ingress_fail_open_enabled() -> bool:
    raw = os.getenv("INGRESS_FAIL_OPEN_STRICT", "").strip().lower()
    return raw in {"1", "true", "t", "yes", "y", "on"}


class ChatCompletionsRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    request_id: Optional[str] = None


# ---------------------------
# Helpers
# ---------------------------


def _tenant_bot_from_headers(request: Request) -> Tuple[str, str]:
    tenant = request.headers.get(TENANT_HEADER) or "default"
    bot = request.headers.get(BOT_HEADER) or "default"
    return tenant, bot


def _blen(s: Optional[str]) -> int:
    return len((s or "").encode("utf-8"))


def _family_for(action: str, redactions: int) -> str:
    if action == "deny":
        return "block"
    if redactions > 0:
        return "sanitize"
    return "allow"


def _normalize_rule_hits(raw_hits: List[Any], raw_decisions: List[Any]) -> List[str]:
    out: List[str] = []

    def add_hit(s: Optional[str]) -> None:
        if s and s not in out:
            out.append(s)

    for h in raw_hits or []:
        if isinstance(h, str):
            add_hit(h)
        elif isinstance(h, dict):
            src = h.get("source") or h.get("origin") or h.get("provider") or h.get("src")
            lst = h.get("list") or h.get("kind") or h.get("type")
            rid = h.get("id") or h.get("rule_id") or h.get("name")
            hint = h.get("reason_hint")
            if src and lst and rid:
                add_hit(f"{src}:{lst}:{rid}")
            elif rid:
                add_hit(str(rid))
            if hint:
                add_hit(str(hint))

    for d in raw_decisions or []:
        if not isinstance(d, dict):
            continue
        src = d.get("source") or d.get("origin") or d.get("provider") or d.get("src")
        lst = d.get("list") or d.get("kind") or d.get("type")
        rid = d.get("id") or d.get("rule_id") or d.get("name")
        if src and lst and rid:
            add_hit(f"{src}:{lst}:{rid}")
        elif rid:
            add_hit(str(rid))

    return out


def _oai_error(message: str, type_: str = "invalid_request_error") -> Dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": type_,
            "param": None,
            "code": None,
        }
    }


def _collect_reason_hints_from_hits(raw_hits: Optional[List[Any]]) -> set[str]:
    hints: set[str] = set()
    for hit in raw_hits or []:
        if not isinstance(hit, dict):
            continue
        rid = hit.get("id")
        hint = hit.get("reason_hint")
        if rid:
            hints.add(str(rid))
        if hint:
            hints.add(str(hint))
    return hints


def _guardrail_completion(content: str, model: str, created: int) -> Dict[str, Any]:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _templated_guardrail_message(
    reason_hints: set[str], model: str, created: int
) -> Optional[Dict[str, Any]]:
    lowered = {h.lower() for h in reason_hints}

    if {"self_harm_support", "safety.self_harm.ideation"} & lowered:
        content = (
            "I'm really sorry that you're feeling this way. I'm not able to help with self-harm, "
            "but you deserve support. If you're in immediate danger, please contact local "
            "emergency services or a crisis hotline right away."
        )
        return _guardrail_completion(content, model, created)

    if {"attachment_boundary", "safety.attachment.love"} & lowered:
        content = (
            "Thank you for sharing that. I'm just software and don't have feelings, "
            "but I'm here to help with information. Would you like ideas for meeting "
            "new people or strengthening your support network?"
        )
        return _guardrail_completion(content, model, created)

    if {"harassment_refusal", "toxicity.revenge.embarrass"} & lowered:
        content = (
            "I can't help with revenge or embarrassing someone. It's better to focus on safe ways "
            "to address conflicts, like talking with a trusted friend, writing down your "
            "feelings, or seeking mediation."
        )
        return _guardrail_completion(content, model, created)

    if {"clarify.workplace_conflict"} & lowered:
        content = (
            "To handle this safely, I need a bit more context. Are you looking for help resolving "
            "the conflict or trying to escalate it? What happened, and what's your relationship "
            "to them (peer, manager, etc.)? Consider documenting incidents, speaking with HR or a "
            "trusted colleague, and keeping communication respectful."
        )
        return _guardrail_completion(content, model, created)

    return None


def _compat_models() -> List[Dict[str, Any]]:
    raw = os.environ.get("OAI_COMPAT_MODELS") or ""
    ids = [s.strip() for s in raw.split(",") if s.strip()] or ["demo"]
    now = int(time.time())
    out: List[Dict[str, Any]] = []
    for mid in ids:
        out.append(
            {
                "id": mid,
                "object": "model",
                "created": now,
                "owned_by": "guardrail",
            }
        )
    return out


def _sse(obj: Dict[str, Any]) -> str:
    return f"data: {json.dumps(obj)}\n\n"


def _chunk_text(s: str, max_len: int) -> List[str]:
    s = s or ""
    out: List[str] = []
    buf: List[str] = []
    cur = 0
    for tok in s.split(" "):
        add = tok if not buf else " " + tok
        if cur + len(add) > max_len and buf:
            out.append("".join(buf))
            buf = [tok]
            cur = len(tok)
        else:
            buf.append(add if buf else tok)
            cur += len(add)
    if buf:
        out.append("".join(buf))
    return out


def _reason_hints(rule_hits: Optional[Union[List[str], Dict[str, Any]]]) -> str:
    """
    Build a compact, bounded CSV of reason keys for headers.
    Accepts either a list of strings, a dict[tag] -> [...patterns], or None.
    """
    if not rule_hits:
        return ""
    if isinstance(rule_hits, dict):
        keys = list(rule_hits.keys())
    elif isinstance(rule_hits, list):
        keys = [str(x) for x in rule_hits]
    else:
        keys = [str(rule_hits)]
    # Normalize and bound to avoid header bloat
    out = ",".join(sorted(set(keys)))
    return out[:200]


# ---------------------------
# Routes
# ---------------------------


@router.get("/models")
async def list_models():
    return {"object": "list", "data": _compat_models()}


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    response: Response,
    body: ChatCompletionsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    OpenAI-compatible chat endpoint with inline guardrails and quotas.
    Supports non-streaming and streaming SSE (stream=true).
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = body.request_id or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    # ---------- Ingress ----------
    joined = "\n".join(f"{m.role}: {m.content}" for m in body.messages or [])
    fail_open_reason: Optional[str] = None
    strict_egress = False

    try:
        sanitized, families, redaction_count, _ = sanitize_text(joined, debug=want_debug)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
            sanitized = dyn_text
            if dyn_fams:
                base = set(families or [])
                base.update(dyn_fams)
                families = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds

        det = evaluate_prompt(sanitized)
        det_action = str(det.get("action", "allow"))
        decisions = list(det.get("decisions", []))
        xformed = det.get("transformed_text", sanitized)
        reason_hints = _collect_reason_hints_from_hits(det.get("rule_hits"))

        flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], decisions)
        det_families = [_normalize_family(h) for h in flat_hits]
        combined_hits = sorted({*(families or []), *det_families})
    except Exception as exc:
        if not _ingress_fail_open_enabled():
            headers = {
                "X-Guardrail-Policy-Version": policy_version,
                "X-Guardrail-Ingress-Action": "error",
                "X-Guardrail-Egress-Action": "skipped",
            }
            raise HTTPException(
                status_code=500,
                detail=_oai_error("Ingress guard failure", type_="internal_error"),
                headers=headers,
            ) from exc

        strict_egress = True
        fail_open_reason = str(exc)
        sanitized = joined
        families = []
        redaction_count = 0
        det_action = "allow"
        decisions = []
        xformed = sanitized
        flat_hits = []
        det_families = []
        combined_hits = []
        reason_hints = set()

    effective_messages = _apply_sanitized_text_to_messages(body.messages or [], xformed)

    if det_action == "deny":
        ingress_action = "deny"
    elif redaction_count:
        ingress_action = "allow"
    else:
        ingress_action = det_action

    ingress_family = _family_for(ingress_action, int(redaction_count or 0))
    inc_decision_family(ingress_family)
    inc_ingress_family(ingress_family)
    inc_decision_family_tenant_bot(ingress_family, tenant_id, bot_id)
    if redaction_count:
        inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

    try:
        ingress_meta: Dict[str, Any] = {"client": get_client_meta(request)}
        if strict_egress:
            ingress_meta["ingress_fail_open"] = True
            if fail_open_reason:
                ingress_meta["ingress_fail_open_reason"] = fail_open_reason[:256]

        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": ingress_action,
                "rule_hits": (combined_hits or None),
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(joined),
                "payload_bytes": int(_blen(joined)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": ingress_meta,
            }
        )
    except Exception:
        pass

    if ingress_action in {"deny", "block_input_only", "clarify"}:
        reason_header = _reason_hints(flat_hits)
        templated = _templated_guardrail_message(reason_hints, body.model, now_ts)
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": "skipped",
            "X-Guardrail-Reason-Hints": reason_header,
            "X-Guardrail-Ingress-Redactions": str(int(redaction_count or 0)),
            "X-Guardrail-Tenant": tenant_id,
            "X-Guardrail-Bot": bot_id,
        }
        if templated is not None:
            headers["X-Guardrail-Decision"] = ingress_action
            response.headers.update(headers)
            return templated

        err_body = _oai_error("Request denied by guardrail policy")
        raise HTTPException(
            status_code=400,
            detail=err_body,
            headers=headers,
        )

    # ---------- Streaming path ----------
    if body.stream:
        client = get_client()
        stream, model_meta = client.chat_stream(
            [m.model_dump() for m in effective_messages], body.model
        )

        sid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created = now_ts
        model_id = body.model

        accum_raw = ""
        last_sanitized = ""
        e_action_final = "allow"
        e_reds_final = 0
        e_hits_final: Optional[List[str]] = None

        def gen() -> Iterable[str]:
            nonlocal accum_raw, last_sanitized
            nonlocal e_action_final, e_reds_final, e_hits_final

            yield _sse(
                {
                    "id": sid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_id,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant"},
                            "finish_reason": None,
                        }
                    ],
                }
            )

            for piece in stream:
                accum_raw += str(piece or "")
                payload, _ = egress_check(accum_raw, debug=want_debug)
                e_action = str(payload.get("action", "allow"))

                if e_action == "deny":
                    e_action_final = "deny"
                    e_reds_final = int(payload.get("redactions") or 0)
                    e_hits_final = list(payload.get("rule_hits") or []) or None
                    yield _sse(
                        {
                            "id": sid,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model_id,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": "content_filter",
                                }
                            ],
                        }
                    )
                    yield "data: [DONE]\n\n"
                    return

                sanitized_full = str(payload.get("text", ""))
                delta = sanitized_full[len(last_sanitized) :]
                if delta:
                    yield _sse(
                        {
                            "id": sid,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model_id,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"content": delta},
                                    "finish_reason": None,
                                }
                            ],
                        }
                    )
                    last_sanitized = sanitized_full
                    e_action_final = "allow"
                    e_reds_final = int(payload.get("redactions") or 0)
                    e_hits_final = list(payload.get("rule_hits") or []) or None

            yield _sse(
                {
                    "id": sid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_id,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
            )
            yield "data: [DONE]\n\n"

            fam = _family_for(e_action_final, int(e_reds_final or 0))
            inc_decision_family(fam)
            inc_egress_family(fam)
            inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
            if e_reds_final:
                inc_redaction("sanitize", direction="egress", amount=float(e_reds_final))
            try:
                stream_meta: Dict[str, Any] = {
                    "provider": model_meta,
                    "client": get_client_meta(request),
                }
                if strict_egress:
                    stream_meta["strict_egress"] = True

                emit_audit_event(
                    {
                        "ts": None,
                        "tenant_id": tenant_id,
                        "bot_id": bot_id,
                        "request_id": req_id,
                        "direction": "egress",
                        "decision": e_action_final,
                        "rule_hits": e_hits_final,
                        "policy_version": policy_version,
                        "status_code": 200,
                        "redaction_count": int(e_reds_final or 0),
                        "hash_fingerprint": content_fingerprint(accum_raw),
                        "payload_bytes": int(_blen(accum_raw)),
                        "sanitized_bytes": int(_blen(last_sanitized)),
                        "meta": stream_meta,
                    }
                )
            except Exception:
                pass

        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": "allow",
            "X-Guardrail-Ingress-Redactions": str(int(redaction_count or 0)),
            "X-Guardrail-Tenant": tenant_id,
            "X-Guardrail-Bot": bot_id,
            # Reason hits & egress redactions finalize at end; keep parity with empties during SSE.
            "X-Guardrail-Reason-Hints": "",
            "X-Guardrail-Egress-Redactions": "0",
            "X-Request-ID": req_id,
        }
        if strict_egress:
            headers["X-Guardrail-Egress-Mode"] = "strict"
        return StreamingResponse(gen(), headers=headers)

    # ---------- Non-streaming path ----------
    client = get_client()
    model_text, model_meta = client.chat([m.model_dump() for m in effective_messages], body.model)

    fp_out = content_fingerprint(model_text)
    reused_flag = False
    if REUSE_ENABLED:
        key = reuse_key(
            request_id=req_id,
            tenant=tenant_id,
            bot=bot_id,
            policy_version=policy_version,
            fingerprint=fp_out,
        )
        reused = reuse_get(key)
        if reused in ("safe", "unsafe"):
            reused_flag = True
            inc_verifier_reuse(reused)
            if reused == "unsafe":
                e_action = "deny"
            else:
                e_action = "allow"
            e_text = model_text
            e_reds = 0
            e_hits = None
        else:
            payload, _ = egress_check(model_text, debug=want_debug)
            e_action = str(payload.get("action", "allow"))
            e_text = str(payload.get("text", ""))
            e_reds = int(payload.get("redactions") or 0)
            e_hits = list(payload.get("rule_hits") or []) or None
    else:
        payload, _ = egress_check(model_text, debug=want_debug)
        e_action = str(payload.get("action", "allow"))
        e_text = str(payload.get("text", ""))
        e_reds = int(payload.get("redactions") or 0)
        e_hits = list(payload.get("rule_hits") or []) or None

    e_family = _family_for(e_action, e_reds)
    inc_decision_family(e_family)
    inc_egress_family(e_family)
    inc_decision_family_tenant_bot(e_family, tenant_id, bot_id)
    if e_reds:
        inc_redaction("sanitize", direction="egress", amount=float(e_reds))

    try:
        egress_meta: Dict[str, Any] = {
            "provider": model_meta,
            "client": get_client_meta(request),
            **({"strict_egress": True} if strict_egress else {}),
            **({"reuse": True} if reused_flag else {}),
        }
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": e_action,
                "rule_hits": e_hits,
                "policy_version": policy_version,
                "verifier_provider": "reuse" if reused_flag else None,
                "redaction_count": e_reds,
                "hash_fingerprint": fp_out,
                "payload_bytes": int(_blen(model_text)),
                "sanitized_bytes": int(_blen(e_text)),
                "meta": egress_meta,
            }
        )
    except Exception:
        pass

    oai_resp: Dict[str, Any] = {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": now_ts,
        "model": body.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": e_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = ingress_action
    response.headers["X-Guardrail-Egress-Action"] = e_action
    response.headers["X-Guardrail-Egress-Redactions"] = str(e_reds)
    response.headers["X-Guardrail-Reason-Hints"] = _reason_hints(e_hits)
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id
    response.headers["X-Request-ID"] = req_id
    if strict_egress:
        response.headers["X-Guardrail-Egress-Mode"] = "strict"
    if reused_flag:
        response.headers["X-Guardrail-Verification-Reused"] = "1"

    return oai_resp


# --- Images (OpenAI-compatible) ----------------------------------------------

_PLACEHOLDER_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
)


class ImagesGenerateRequest(BaseModel):
    model: Optional[str] = None
    prompt: str
    n: Optional[int] = 1
    size: Optional[str] = "256x256"
    response_format: Optional[str] = "b64_json"
    user: Optional[str] = None


@router.post("/images/generations")
async def images_generations(
    request: Request,
    response: Response,
    body: ImagesGenerateRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    """
    /v1/images/generations with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())
    n = max(1, int(body.n or 1))

    # Ingress guard
    sanitized, families, redaction_count, _ = sanitize_text(body.prompt, debug=want_debug)
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    det = evaluate_prompt(sanitized)
    det_action = str(det.get("action", "allow"))
    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], det.get("decisions", []) or [])

    if det_action == "deny":
        fam = _family_for("deny", 0)
        inc_decision_family(fam)
        inc_ingress_family(fam)
        inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": "deny",
                    "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                    "policy_version": policy_version,
                    "redaction_count": 0,
                    "hash_fingerprint": content_fingerprint(body.prompt),
                    "payload_bytes": int(_blen(body.prompt)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {
                        "endpoint": "images/generations",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": "deny",
            "X-Guardrail-Egress-Action": "skipped",
        }
        raise HTTPException(
            status_code=400,
            detail=_oai_error("Request denied by guardrail policy"),
            headers=headers,
        )

    fam = _family_for("allow", int(redaction_count or 0))
    inc_decision_family(fam)
    inc_ingress_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
    if redaction_count:
        inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": "allow",
                "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(body.prompt),
                "payload_bytes": int(_blen(body.prompt)),
                "sanitized_bytes": int(_blen(sanitized)),
                "meta": {
                    "endpoint": "images/generations",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    data = [{"b64_json": _PLACEHOLDER_PNG_B64} for _ in range(n)]
    total_bytes = sum(len(base64.b64decode(d["b64_json"])) for d in data)

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": "allow",
                "rule_hits": None,
                "policy_version": policy_version,
                "redaction_count": 0,
                "hash_fingerprint": content_fingerprint("image/" + str(n)),
                "payload_bytes": int(total_bytes),
                "sanitized_bytes": int(total_bytes),
                "meta": {
                    "endpoint": "images/generations",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Redactions"] = "0"
    response.headers["X-Guardrail-Reason-Hints"] = ""
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return {"created": now_ts, "data": data}


@router.post("/images/edits")
async def images_edits(
    request: Request,
    response: Response,
    image: Optional[UploadFile] = File(default=None),
    prompt: Optional[str] = Form(default=""),
    n: Optional[int] = Form(default=1),
    size: Optional[str] = Form(default="256x256"),
    response_format: Optional[str] = Form(default="b64_json"),
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    """
    /v1/images/edits with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())
    n_final = max(1, int(n or 1))
    text = prompt or ""

    sanitized, families, redaction_count, _ = sanitize_text(text, debug=want_debug)
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    det = evaluate_prompt(sanitized)
    det_action = str(det.get("action", "allow"))
    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], det.get("decisions", []) or [])

    if det_action == "deny":
        fam = _family_for("deny", 0)
        inc_decision_family(fam)
        inc_ingress_family(fam)
        inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": "deny",
                    "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                    "policy_version": policy_version,
                    "redaction_count": 0,
                    "hash_fingerprint": content_fingerprint(text),
                    "payload_bytes": int(_blen(text)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {
                        "endpoint": "images/edits",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": "deny",
            "X-Guardrail-Egress-Action": "skipped",
        }
        raise HTTPException(
            status_code=400,
            detail=_oai_error("Request denied by guardrail policy"),
            headers=headers,
        )

    fam = _family_for("allow", int(redaction_count or 0))
    inc_decision_family(fam)
    inc_ingress_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
    if redaction_count:
        inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": "allow",
                "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(text),
                "payload_bytes": int(_blen(text)),
                "sanitized_bytes": int(_blen(sanitized)),
                "meta": {
                    "endpoint": "images/edits",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    data = [{"b64_json": _PLACEHOLDER_PNG_B64} for _ in range(n_final)]
    total_bytes = sum(len(base64.b64decode(d["b64_json"])) for d in data)

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": "allow",
                "rule_hits": None,
                "policy_version": policy_version,
                "redaction_count": 0,
                "hash_fingerprint": content_fingerprint("image-edit/" + str(n_final)),
                "payload_bytes": int(total_bytes),
                "sanitized_bytes": int(total_bytes),
                "meta": {
                    "endpoint": "images/edits",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Redactions"] = "0"
    response.headers["X-Guardrail-Reason-Hints"] = ""
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return {"created": now_ts, "data": data}


@router.post("/images/variations")
async def images_variations(
    request: Request,
    response: Response,
    image: UploadFile = File(...),
    n: Optional[int] = Form(default=1),
    size: Optional[str] = Form(default="256x256"),
    response_format: Optional[str] = Form(default="b64_json"),
    prompt: Optional[str] = Form(default=""),
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
) -> Dict[str, Any]:
    """
    /v1/images/variations with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())
    n_final = max(1, int(n or 1))
    text = prompt or ""

    sanitized, families, redaction_count, _ = sanitize_text(text, debug=want_debug)
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    det = evaluate_prompt(sanitized)
    det_action = str(det.get("action", "allow"))
    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], det.get("decisions", []) or [])

    if det_action == "deny":
        fam = _family_for("deny", 0)
        inc_decision_family(fam)
        inc_ingress_family(fam)
        inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": "deny",
                    "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                    "policy_version": policy_version,
                    "redaction_count": 0,
                    "hash_fingerprint": content_fingerprint(text),
                    "payload_bytes": int(_blen(text)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {
                        "endpoint": "images/variations",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": "deny",
            "X-Guardrail-Egress-Action": "skipped",
        }
        raise HTTPException(
            status_code=400,
            detail=_oai_error("Request denied by guardrail policy"),
            headers=headers,
        )

    fam = _family_for("allow", int(redaction_count or 0))
    inc_decision_family(fam)
    inc_ingress_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
    if redaction_count:
        inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": "allow",
                "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(text),
                "payload_bytes": int(_blen(text)),
                "sanitized_bytes": int(_blen(sanitized)),
                "meta": {
                    "endpoint": "images/variations",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    data = [{"b64_json": _PLACEHOLDER_PNG_B64} for _ in range(n_final)]
    total_bytes = sum(len(base64.b64decode(d["b64_json"])) for d in data)

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": "allow",
                "rule_hits": None,
                "policy_version": policy_version,
                "redaction_count": 0,
                "hash_fingerprint": content_fingerprint("image-var/" + str(n_final)),
                "payload_bytes": int(total_bytes),
                "sanitized_bytes": int(total_bytes),
                "meta": {
                    "endpoint": "images/variations",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Redactions"] = "0"
    response.headers["X-Guardrail-Reason-Hints"] = ""
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return {"created": now_ts, "data": data}


# --- Azure OpenAI–compatible endpoints ---------------------------------------

from fastapi import APIRouter as _APIRouter  # noqa: E402

azure_router = _APIRouter(prefix="/openai/deployments", tags=["azure-openai-compat"])


class _AzureChatBody(BaseModel):
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    request_id: Optional[str] = None


class _AzureEmbeddingsBody(BaseModel):
    input: Any  # normalized via EmbeddingsRequest validator


@azure_router.post("/{deployment_id}/chat/completions")
async def azure_chat_completions(
    request: Request,
    response: Response,
    deployment_id: str,
    body: _AzureChatBody,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    Azure-style chat endpoint. Delegates to /v1/chat/completions.
    """
    mapped = ChatCompletionsRequest(
        model=deployment_id,
        messages=body.messages,
        stream=bool(body.stream),
        request_id=body.request_id,
    )
    api_version = request.query_params.get("api-version") or ""
    result = await chat_completions(request, response, mapped, x_debug)
    if not isinstance(result, StreamingResponse) and api_version:
        response.headers["X-Azure-API-Version"] = api_version
    return result


@azure_router.post("/{deployment_id}/embeddings")
async def azure_embeddings(
    request: Request,
    response: Response,
    deployment_id: str,
    body: _AzureEmbeddingsBody,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    Azure-style embeddings endpoint.
    """
    mapped = EmbeddingsRequest(model=deployment_id, input=body.input)
    api_version = request.query_params.get("api-version") or ""
    result = await create_embeddings(request, response, mapped, x_debug)
    if isinstance(result, dict) and api_version:
        response.headers["X-Azure-API-Version"] = api_version
    return result


# --- Moderations (OpenAI-compatible) -----------------------------------------


class ModerationsRequest(BaseModel):
    model: str
    input: Union[str, List[str]]

    @field_validator("input", mode="before")
    @classmethod
    def _normalize_input(cls, v: Any) -> List[str]:
        if v is None:
            return [""]
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]


@router.post("/moderations")
async def create_moderation(
    request: Request,
    response: Response,
    body: ModerationsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    /v1/moderations with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    results: List[Dict[str, Any]] = []
    total_redactions = 0

    for item in body.input:
        sanitized, fams, redaction_count, _ = sanitize_text(item, debug=want_debug)
        total_redactions += int(redaction_count or 0)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
            sanitized = dyn_text
            if dyn_fams:
                base = set(fams or [])
                base.update(dyn_fams)
                fams = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds
                total_redactions += int(dyn_reds or 0)

        det = evaluate_prompt(sanitized)
        det_action = str(det.get("action", "allow"))
        decisions = list(det.get("decisions", []))
        flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], decisions)

        if det_action == "deny":
            ingress_action = "deny"
        elif redaction_count:
            ingress_action = "allow"
        else:
            ingress_action = det_action

        fam = _family_for(ingress_action, int(redaction_count or 0))
        inc_decision_family(fam)
        inc_ingress_family(fam)
        inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
        if redaction_count:
            inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": ingress_action,
                    "rule_hits": (sorted({_normalize_family(h) for h in flat_hits}) or None),
                    "policy_version": policy_version,
                    "redaction_count": int(redaction_count or 0),
                    "hash_fingerprint": content_fingerprint(item),
                    "payload_bytes": int(_blen(item)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {
                        "endpoint": "moderations",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass

        flagged = ingress_action == "deny"
        violence = any("weapon" in h or "explosive" in h for h in flat_hits)
        categories = {
            "harassment": False,
            "hate": False,
            "self-harm": False,
            "sexual": False,
            "violence": bool(violence),
        }
        scores = {
            k: (0.98 if (k == "violence" and violence) else (0.0 if not flagged else 0.6))
            for k in categories.keys()
        }

        results.append(
            {
                "flagged": bool(flagged),
                "categories": categories,
                "category_scores": scores,
            }
        )

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    final_flag = any(r["flagged"] for r in results)
    response.headers["X-Guardrail-Ingress-Action"] = "deny" if final_flag else "allow"
    response.headers["X-Guardrail-Egress-Action"] = "skipped"
    response.headers["X-Guardrail-Egress-Redactions"] = "0"
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(total_redactions))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return {
        "id": f"modr-{uuid.uuid4().hex[:12]}",
        "model": body.model,
        "created": now_ts,
        "results": results,
    }


# --- Embeddings (OpenAI-compatible) ------------------------------------------

import hashlib as _hashlib  # noqa: E402
import os as _os  # noqa: E402
import random as _random  # noqa: E402


class EmbeddingsRequest(BaseModel):
    model: str
    input: Union[str, List[str]]

    @field_validator("input", mode="before")
    @classmethod
    def _normalize_input(cls, v: Any) -> List[str]:
        if v is None:
            return [""]
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]


@router.post("/embeddings")
async def create_embeddings(
    request: Request,
    response: Response,
    body: EmbeddingsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    /v1/embeddings with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())
    dim = int(_os.environ.get("OAI_COMPAT_EMBED_DIM") or "1536")

    data: List[Dict[str, Any]] = []
    total_redactions = 0

    for idx, item in enumerate(body.input):
        sanitized, fams, redaction_count, _ = sanitize_text(item, debug=want_debug)
        total_redactions += int(redaction_count or 0)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
            sanitized = dyn_text
            if dyn_fams:
                base = set(fams or [])
                base.update(dyn_fams)
                fams = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds
                total_redactions += int(dyn_reds or 0)

        det = evaluate_prompt(sanitized)
        det_action = str(det.get("action", "allow"))
        fam = _family_for(
            "deny" if det_action == "deny" else "allow",
            int(redaction_count or 0),
        )
        inc_decision_family(fam)
        inc_ingress_family(fam)
        inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
        if redaction_count:
            inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": ("deny" if det_action == "deny" else "allow"),
                    "rule_hits": None,
                    "policy_version": policy_version,
                    "redaction_count": int(redaction_count or 0),
                    "hash_fingerprint": content_fingerprint(item),
                    "payload_bytes": int(_blen(item)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {
                        "endpoint": "embeddings",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass

        if det_action == "deny":
            headers = {
                "X-Guardrail-Policy-Version": policy_version,
                "X-Guardrail-Ingress-Action": "deny",
                "X-Guardrail-Egress-Action": "skipped",
            }
            raise HTTPException(
                status_code=400,
                detail=_oai_error("Request denied by guardrail policy"),
                headers=headers,
            )

        seed = int.from_bytes(
            _hashlib.sha256(item.encode("utf-8")).digest()[:8],
            "big",
        )
        rng = _random.Random(seed)
        vec = [rng.uniform(-0.01, 0.01) for _ in range(dim)]
        data.append({"object": "embedding", "embedding": vec, "index": idx})

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Action"] = "allow"
    response.headers["X-Guardrail-Egress-Redactions"] = "0"
    response.headers["X-Guardrail-Reason-Hints"] = ""
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(total_redactions))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return {
        "object": "list",
        "data": data,
        "model": body.model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
        "created": now_ts,
    }


# --- Completions (OpenAI-compatible) -----------------------------------------


class CompletionsRequest(BaseModel):
    model: str
    prompt: str
    stream: Optional[bool] = False
    request_id: Optional[str] = None


@router.post("/completions")
async def completions(
    request: Request,
    response: Response,
    body: CompletionsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    /v1/completions with quotas + guard.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = body.request_id or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    # ---------- Ingress ----------
    joined = f"user: {body.prompt}"

    sanitized, families, redaction_count, _ = sanitize_text(joined, debug=want_debug)
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
        sanitized = dyn_text
        if dyn_fams:
            base = set(families or [])
            base.update(dyn_fams)
            families = sorted(base)
        if dyn_reds:
            redaction_count = (redaction_count or 0) + dyn_reds

    det = evaluate_prompt(sanitized)
    det_action = str(det.get("action", "allow"))
    xformed = det.get("transformed_text", sanitized)
    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], det.get("decisions", []) or [])
    det_families = [_normalize_family(h) for h in flat_hits]
    combined_hits = sorted({*(families or []), *det_families})

    if det_action == "deny":
        ingress_action = "deny"
    elif redaction_count:
        ingress_action = "allow"
    else:
        ingress_action = det_action

    fam = _family_for(ingress_action, int(redaction_count or 0))
    inc_decision_family(fam)
    inc_ingress_family(fam)
    inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
    if redaction_count:
        inc_redaction("sanitize", direction="ingress", amount=float(redaction_count))

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "ingress",
                "decision": ingress_action,
                "rule_hits": (combined_hits or None),
                "policy_version": policy_version,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(joined),
                "payload_bytes": int(_blen(joined)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": {
                    "endpoint": "completions",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    if ingress_action == "deny":
        err_body = _oai_error("Request denied by guardrail policy")
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": "skipped",
        }
        raise HTTPException(
            status_code=400,
            detail=err_body,
            headers=headers,
        )

    client = get_client()
    messages = [{"role": "user", "content": body.prompt}]
    model_text, model_meta = client.chat(messages, body.model)

    payload, _ = egress_check(model_text, debug=want_debug)
    e_action = str(payload.get("action", "allow"))
    e_text = str(payload.get("text", ""))
    e_reds = int(payload.get("redactions") or 0)
    e_hits = list(payload.get("rule_hits") or []) or None

    e_fam = _family_for(e_action, e_reds)
    inc_decision_family(e_fam)
    inc_egress_family(e_fam)
    inc_decision_family_tenant_bot(e_fam, tenant_id, bot_id)
    if e_reds:
        inc_redaction("sanitize", direction="egress", amount=float(e_reds))

    try:
        emit_audit_event(
            {
                "ts": None,
                "tenant_id": tenant_id,
                "bot_id": bot_id,
                "request_id": req_id,
                "direction": "egress",
                "decision": e_action,
                "rule_hits": e_hits,
                "policy_version": policy_version,
                "redaction_count": e_reds,
                "hash_fingerprint": content_fingerprint(model_text),
                "payload_bytes": int(_blen(model_text)),
                "sanitized_bytes": int(_blen(e_text)),
                "meta": {
                    "provider": model_meta,
                    "endpoint": "completions",
                    "client": get_client_meta(request),
                },
            }
        )
    except Exception:
        pass

    if body.stream:
        sid = f"cmpl-{uuid.uuid4().hex[:12]}"
        created = now_ts
        model_id = body.model

        def gen() -> Iterable[str]:
            for piece in _chunk_text(e_text, max_len=60):
                yield _sse(
                    {
                        "id": sid,
                        "object": "text_completion",
                        "created": created,
                        "model": model_id,
                        "choices": [{"index": 0, "text": piece, "finish_reason": None}],
                    }
                )
            yield _sse(
                {
                    "id": sid,
                    "object": "text_completion",
                    "created": created,
                    "model": model_id,
                    "choices": [{"index": 0, "text": "", "finish_reason": "stop"}],
                }
            )
            yield "data: [DONE]\n\n"

        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": e_action,
            "X-Guardrail-Egress-Redactions": str(e_reds),
            "X-Guardrail-Ingress-Redactions": str(int(redaction_count or 0)),
            "X-Guardrail-Tenant": tenant_id,
            "X-Guardrail-Bot": bot_id,
            # We’re chunking a precomputed string here; still keep hints empty for consistency.
            "X-Guardrail-Reason-Hints": "",
        }
        return StreamingResponse(gen(), headers=headers)

    resp: Dict[str, Any] = {
        "id": f"cmpl-{uuid.uuid4().hex[:12]}",
        "object": "text_completion",
        "created": now_ts,
        "model": body.model,
        "choices": [{"index": 0, "text": e_text, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    response.headers["X-Guardrail-Policy-Version"] = policy_version
    response.headers["X-Guardrail-Ingress-Action"] = ingress_action
    response.headers["X-Guardrail-Egress-Action"] = e_action
    response.headers["X-Guardrail-Egress-Redactions"] = str(e_reds)
    response.headers["X-Guardrail-Reason-Hints"] = _reason_hints(e_hits)
    response.headers["X-Guardrail-Ingress-Redactions"] = str(int(redaction_count or 0))
    response.headers["X-Guardrail-Tenant"] = tenant_id
    response.headers["X-Guardrail-Bot"] = bot_id

    return resp
