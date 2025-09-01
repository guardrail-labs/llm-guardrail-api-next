# file: app/routes/openai_compat.py
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.services.audit_forwarder import emit_event as emit_audit_event
from app.services.detectors import evaluate_prompt
from app.services.egress import egress_check
from app.services.llm_client import get_client
from app.services.policy import (
    _normalize_family,
    current_rules_version,
    sanitize_text,
)
from app.services.threat_feed import (
    apply_dynamic_redactions,
    threat_feed_enabled,
)
from app.services.verifier import content_fingerprint
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
)

router = APIRouter(prefix="/v1", tags=["openai-compat"])


# ---------------------------
# Models (subset for compat)
# ---------------------------


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


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
    """
    Flatten detector hits/decisions to 'source:list:id' strings.
    """
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
            if src and lst and rid:
                add_hit(f"{src}:{lst}:{rid}")
            elif rid:
                add_hit(str(rid))

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
    return {"error": {"message": message, "type": type_, "param": None, "code": None}}


def _compat_models() -> List[Dict[str, Any]]:
    """
    Return OpenAI-style model objects.
    Configure via OAI_COMPAT_MODELS="gpt-4o-mini,gpt-4o" or default to ["demo"].
    """
    import os

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


def _chunk_text(s: str, max_len: int = 60) -> List[str]:
    """
    Simple chunker that preserves spaces reasonably well for demo streaming.
    """
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


# ---------------------------
# Routes
# ---------------------------


@router.get("/models")
async def list_models():
    """
    Minimal OpenAI-compatible /v1/models listing.
    """
    return {"object": "list", "data": _compat_models()}


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    body: ChatCompletionsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    OpenAI-compatible chat endpoint with inline guardrails.
    Supports non-streaming and streaming SSE (stream=true).
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()

    req_id = body.request_id or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    # ---------- Ingress ----------
    joined = "\n".join(f"{m.role}: {m.content}" for m in body.messages or [])

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

    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], decisions)
    det_families = [_normalize_family(h) for h in flat_hits]
    combined_hits = sorted({*(families or []), *det_families})

    if det_action == "deny":
        ingress_action = "deny"
    elif redaction_count:
        ingress_action = "allow"
    else:
        ingress_action = det_action

    ingress_family = _family_for(ingress_action, int(redaction_count or 0))
    inc_decision_family(ingress_family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, ingress_family)

    # Audit ingress
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
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(joined),
                "payload_bytes": int(_blen(joined)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": {},
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
        raise HTTPException(status_code=400, detail=err_body, headers=headers)

    # ---------- Streaming path ----------
    if body.stream:
        client = get_client()
        stream, model_meta = client.chat_stream(
            [m.model_dump() for m in body.messages], body.model
        )

        sid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created = now_ts
        model_id = body.model

        # Rolling sanitizer across the cumulative output
        accum_raw = ""
        last_sanitized = ""
        e_action_final = "allow"
        e_reds_final = 0
        e_hits_final: Optional[List[str]] = None

        def gen() -> Iterable[str]:
            nonlocal accum_raw, last_sanitized
            nonlocal e_action_final, e_reds_final, e_hits_final

            # First chunk announces role
            yield _sse(
                {
                    "id": sid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_id,
                    "choices": [
                        {"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}
                    ],
                }
            )

            # Stream model deltas -> cumulative egress_check -> stream sanitized deltas
            for piece in stream:
                accum_raw += str(piece or "")
                payload, _ = egress_check(accum_raw, debug=want_debug)
                e_action = str(payload.get("action", "allow"))

                if e_action == "deny":
                    # Stop immediately with content_filter
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
                                {"index": 0, "delta": {}, "finish_reason": "content_filter"}
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

            # Final chunk with finish_reason=stop
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

            # Audit + metrics after stream ends
            fam = _family_for(e_action_final, int(e_reds_final or 0))
            inc_decision_family(fam)
            inc_decision_family_tenant_bot(tenant_id, bot_id, fam)
            try:
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
                        "verifier_provider": None,
                        "fallback_used": None,
                        "status_code": 200,
                        "redaction_count": int(e_reds_final or 0),
                        "hash_fingerprint": content_fingerprint(accum_raw),
                        "payload_bytes": int(_blen(accum_raw)),
                        "sanitized_bytes": int(_blen(last_sanitized)),
                        "meta": {"provider": model_meta},
                    }
                )
            except Exception:
                pass

        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Guardrail-Policy-Version": policy_version,
            # We can only know final egress action after streaming completes.
            # Default the header to "allow" for compatibility.
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": "allow",
        }
        return StreamingResponse(gen(), headers=headers)

    # ---------- Non-streaming path ----------
    client = get_client()
    model_text, model_meta = client.chat([m.model_dump() for m in body.messages], body.model)

    payload, _ = egress_check(model_text, debug=want_debug)
    e_action = str(payload.get("action", "allow"))
    e_text = str(payload.get("text", ""))
    e_reds = int(payload.get("redactions") or 0)
    e_hits = list(payload.get("rule_hits") or []) or None

    e_family = _family_for(e_action, e_reds)
    inc_decision_family(e_family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, e_family)

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
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": e_reds,
                "hash_fingerprint": content_fingerprint(model_text),
                "payload_bytes": int(_blen(model_text)),
                "sanitized_bytes": int(_blen(e_text)),
                "meta": {"provider": model_meta},
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
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    # Attach guard signals via headers for non-streaming
    request.state._extra_headers = {
        "X-Guardrail-Policy-Version": policy_version,
        "X-Guardrail-Ingress-Action": ingress_action,
        "X-Guardrail-Egress-Action": e_action,
        "X-Guardrail-Egress-Redactions": str(e_reds),
    }

    return oai_resp


# --- Text Completions (OpenAI-compatible) ------------------------------------


class CompletionsRequest(BaseModel):
    model: str
    prompt: str
    stream: Optional[bool] = False
    request_id: Optional[str] = None


@router.post("/completions")
async def completions(
    request: Request,
    body: CompletionsRequest,
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
):
    """
    Minimal OpenAI-compatible /v1/completions:
    - Maps prompt -> chat-style single user message.
    - Applies the same ingress/egress guard, metrics, and audit.
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
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(
            sanitized, debug=want_debug
        )
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
    flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [],
                                     det.get("decisions", []) or [])
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
    inc_decision_family_tenant_bot(tenant_id, bot_id, fam)

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
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": int(redaction_count or 0),
                "hash_fingerprint": content_fingerprint(joined),
                "payload_bytes": int(_blen(joined)),
                "sanitized_bytes": int(_blen(xformed)),
                "meta": {"endpoint": "completions"},
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
        raise HTTPException(status_code=400, detail=err_body, headers=headers)

    # ---------- Model call ----------
    client = get_client()
    messages = [{"role": "user", "content": body.prompt}]
    model_text, model_meta = client.chat(messages, body.model)

    # ---------- Egress ----------
    payload, _ = egress_check(model_text, debug=want_debug)
    e_action = str(payload.get("action", "allow"))
    e_text = str(payload.get("text", ""))
    e_reds = int(payload.get("redactions") or 0)
    e_hits = list(payload.get("rule_hits") or []) or None

    e_fam = _family_for(e_action, e_reds)
    inc_decision_family(e_fam)
    inc_decision_family_tenant_bot(tenant_id, bot_id, e_fam)

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
                "verifier_provider": None,
                "fallback_used": None,
                "status_code": 200,
                "redaction_count": e_reds,
                "hash_fingerprint": content_fingerprint(model_text),
                "payload_bytes": int(_blen(model_text)),
                "sanitized_bytes": int(_blen(e_text)),
                "meta": {"provider": model_meta, "endpoint": "completions"},
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
                        "choices": [
                            {
                                "index": 0,
                                "text": piece,
                                "finish_reason": None,
                            }
                        ],
                    }
                )
            yield _sse(
                {
                    "id": sid,
                    "object": "text_completion",
                    "created": created,
                    "model": model_id,
                    "choices": [
                        {"index": 0, "text": "", "finish_reason": "stop"}
                    ],
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
        }
        return StreamingResponse(gen(), headers=headers)

    # Non-streaming response (OpenAI-ish)
    resp: Dict[str, Any] = {
        "id": f"cmpl-{uuid.uuid4().hex[:12]}",
        "object": "text_completion",
        "created": now_ts,
        "model": body.model,
        "choices": [
            {"index": 0, "text": e_text, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    request.state._extra_headers = {
        "X-Guardrail-Policy-Version": policy_version,
        "X-Guardrail-Ingress-Action": ingress_action,
        "X-Guardrail-Egress-Action": e_action,
        "X-Guardrail-Egress-Redactions": str(e_reds),
    }
    return resp


# --- Moderations (OpenAI-compatible) -----------------------------------------

from typing import Union  # noqa: E402  (keep import local to avoid reorder churn)

from pydantic import field_validator  # noqa: E402


class ModerationsRequest(BaseModel):
    model: str
    # OpenAI accepts str or list[str]; we normalize in a validator.
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
    body: ModerationsRequest,
    x_debug: Optional[str] = Header(default=None, alias="X-Debug", convert_underscores=False),
):
    """
    Minimal OpenAI-compatible /v1/moderations.

    We treat 'deny' from detectors as flagged=True. Redactions do not flag,
    but still count toward 'sanitize' family for metrics.
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    results: List[Dict[str, Any]] = []

    for item in body.input:
        # Ingress pass
        sanitized, fams, redaction_count, _ = sanitize_text(item, debug=want_debug)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(sanitized, debug=want_debug)
            sanitized = dyn_text
            if dyn_fams:
                base = set(fams or [])
                base.update(dyn_fams)
                fams = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds

        det = evaluate_prompt(sanitized)
        det_action = str(det.get("action", "allow"))
        decisions = list(det.get("decisions", []))
        flat_hits = _normalize_rule_hits(det.get("rule_hits", []) or [], decisions)

        # Decision mapping
        if det_action == "deny":
            ingress_action = "deny"
        elif redaction_count:
            ingress_action = "allow"
        else:
            ingress_action = det_action

        fam = _family_for(ingress_action, int(redaction_count or 0))
        inc_decision_family(fam)
        inc_decision_family_tenant_bot(tenant_id, bot_id, fam)

        # Audit each item (ingress)
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
                    "verifier_provider": None,
                    "fallback_used": None,
                    "status_code": 200,
                    "redaction_count": int(redaction_count or 0),
                    "hash_fingerprint": content_fingerprint(item),
                    "payload_bytes": int(_blen(item)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {"endpoint": "moderations"},
                }
            )
        except Exception:
            pass

        # OpenAI-ish categories (minimal; extend as detectors grow)
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

    return {
        "id": f"modr-{uuid.uuid4().hex[:12]}",
        "model": body.model,
        "created": now_ts,
        "results": results,
    }


# --- Embeddings (OpenAI-compatible) ------------------------------------------


class EmbeddingsRequest(BaseModel):
    model: str
    # OpenAI accepts str or list[str]
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


def _demo_embed(s: str, dim: int = 8) -> List[float]:
    """
    Deterministic, local-only toy embedding for demos/tests.
    Produces small floats from a rolling hash.
    """
    h = 2166136261
    for ch in (s or ""):
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    # spread bits into dim floats in [0, 1)
    out: List[float] = []
    cur = h
    for _ in range(dim):
        cur = (cur * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((cur % 1000) / 1000.0)
    return out


@router.post("/embeddings")
async def create_embeddings(
    request: Request,
    body: EmbeddingsRequest,
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
):
    """
    Minimal OpenAI-compatible /v1/embeddings.

    - Applies ingress guard (sanitize + optional threat feed).
    - Emits per-tenant/bot decision-family metrics.
    - Audits each item (ingress).
    - Returns deterministic local vectors (no external calls).
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    now_ts = int(time.time())

    data_items: List[Dict[str, Any]] = []
    idx = 0

    for raw in body.input:
        # Ingress pass
        sanitized, fams, redaction_count, _ = sanitize_text(raw, debug=want_debug)
        if threat_feed_enabled():
            dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(
                sanitized, debug=want_debug
            )
            sanitized = dyn_text
            if dyn_fams:
                base = set(fams or [])
                base.update(dyn_fams)
                fams = sorted(base)
            if dyn_reds:
                redaction_count = (redaction_count or 0) + dyn_reds

        # Detectors (to surface rule families even for embeddings)
        det = evaluate_prompt(sanitized)
        det_action = str(det.get("action", "allow"))
        det_hits = _normalize_rule_hits(
            det.get("rule_hits", []) or [],
            det.get("decisions", []) or [],
        )
        combined_hits = sorted(
            {*(fams or []), *[_normalize_family(h) for h in det_hits]}
        )

        # Decision mapping (deny vs allow w/ sanitize)
        if det_action == "deny":
            ingress_action = "deny"
        elif redaction_count:
            ingress_action = "allow"
        else:
            ingress_action = det_action

        fam = _family_for(ingress_action, int(redaction_count or 0))
        inc_decision_family(fam)
        inc_decision_family_tenant_bot(tenant_id, bot_id, fam)

        # Audit (ingress) — per item
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
                    "verifier_provider": None,
                    "fallback_used": None,
                    "status_code": 200,
                    "redaction_count": int(redaction_count or 0),
                    "hash_fingerprint": content_fingerprint(raw),
                    "payload_bytes": int(_blen(raw)),
                    "sanitized_bytes": int(_blen(sanitized)),
                    "meta": {"endpoint": "embeddings"},
                }
            )
        except Exception:
            pass

        # For embeddings, we only deny when policy says so.
        # Otherwise, we embed the sanitized text.
        if ingress_action == "deny":
            # Match OpenAI error style at the request level.
            # If any item is denied, fail the whole request consistently.
            err_body = {
                "error": {
                    "message": "Request denied by guardrail policy",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": None,
                }
            }
            headers = {
                "X-Guardrail-Policy-Version": policy_version,
                "X-Guardrail-Ingress-Action": ingress_action,
                "X-Guardrail-Egress-Action": "skipped",
            }
            raise HTTPException(status_code=400, detail=err_body, headers=headers)

        vec = _demo_embed(sanitized, dim=8)
        data_items.append(
            {
                "object": "embedding",
                "index": idx,
                "embedding": vec,
            }
        )
        idx += 1

    # Standard OpenAI-ish response
    resp: Dict[str, Any] = {
        "object": "list",
        "data": data_items,
        "model": body.model,
        "usage": {
            "prompt_tokens": 0,
            "total_tokens": 0,
        },
        "created": now_ts,
    }

    # Surface guard metadata via headers (consistent with chat)
    request.state._extra_headers = {
        "X-Guardrail-Policy-Version": policy_version,
        "X-Guardrail-Ingress-Action": "allow",  # per-item signals already captured in audit
        "X-Guardrail-Egress-Action": "skipped",  # embeddings are non-text egress here
        "X-Guardrail-Egress-Redactions": "0",
    }
    return resp
