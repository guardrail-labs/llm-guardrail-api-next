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
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    Form,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from app.services.audit_forwarder import emit_audit_event
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
from app.services.quotas import quota_check_and_consume
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.shared.request_meta import get_client_meta
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
    inc_quota_reject_tenant_bot,
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


def _normalize_rule_hits(
    raw_hits: List[Any], raw_decisions: List[Any]
) -> List[str]:
    out: List[str] = []

    def add_hit(s: Optional[str]) -> None:
        if s and s not in out:
            out.append(s)

    for h in raw_hits or []:
        if isinstance(h, str):
            add_hit(h)
        elif isinstance(h, dict):
            src = (
                h.get("source")
                or h.get("origin")
                or h.get("provider")
                or h.get("src")
            )
            lst = h.get("list") or h.get("kind") or h.get("type")
            rid = h.get("id") or h.get("rule_id") or h.get("name")
            if src and lst and rid:
                add_hit(f"{src}:{lst}:{rid}")
            elif rid:
                add_hit(str(rid))

    for d in raw_decisions or []:
        if not isinstance(d, dict):
            continue
        src = (
            d.get("source")
            or d.get("origin")
            or d.get("provider")
            or d.get("src")
        )
        lst = d.get("list") or d.get("kind") or d.get("type")
        rid = d.get("id") or d.get("rule_id") or d.get("name")
        if src and lst and rid:
            add_hit(f"{src}:{lst}:{rid}")
        elif rid:
            add_hit(str(rid))

    return out


def _oai_error(
    message: str, type_: str = "invalid_request_error"
) -> Dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": type_,
            "param": None,
            "code": None,
        }
    }


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
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
):
    """
    OpenAI-compatible chat endpoint with inline guardrails and quotas.
    Supports non-streaming and streaming SSE (stream=true).
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()
    req_id = (
        body.request_id
        or request.headers.get("X-Request-ID")
        or str(uuid.uuid4())
    )
    now_ts = int(time.time())

    # ---------- Quotas (pre-ingress) ----------
    allowed, retry_after, _ = quota_check_and_consume(
        request, tenant_id, bot_id
    )
    if not allowed:
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": "deny",
                    "rule_hits": None,
                    "policy_version": policy_version,
                    "status_code": 429,
                    "redaction_count": 0,
                    "hash_fingerprint": content_fingerprint("quota"),
                    "payload_bytes": 0,
                    "sanitized_bytes": 0,
                    "meta": {
                        "endpoint": "chat/completions",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass
        headers = {
            "Retry-After": str(retry_after),
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": "deny",
            "X-Guardrail-Egress-Action": "skipped",
        }
        detail = {
            "code": "rate_limited",
            "detail": "Per-tenant quota exceeded",
            "retry_after": int(retry_after),
            "request_id": req_id,
        }
        raise HTTPException(status_code=429, detail=detail, headers=headers)

    # ---------- Ingress ----------
    joined = "\n".join(f"{m.role}: {m.content}" for m in body.messages or [])
    sanitized, families, redaction_count, _ = sanitize_text(
        joined, debug=want_debug
    )
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
    decisions = list(det.get("decisions", []))
    xformed = det.get("transformed_text", sanitized)

    flat_hits = _normalize_rule_hits(
        det.get("rule_hits", []) or [], decisions
    )
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
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(ingress_family, tenant_id, bot_id)

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
                "meta": {"client": get_client_meta(request)},
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

    # ---------- Streaming path ----------
    if body.stream:
        client = get_client()
        stream, model_meta = client.chat_stream(
            [m.model_dump() for m in body.messages], body.model
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
                    e_hits_final = (
                        list(payload.get("rule_hits") or []) or None
                    )
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
                delta = sanitized_full[len(last_sanitized):]
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
                    e_hits_final = (
                        list(payload.get("rule_hits") or []) or None
                    )

            yield _sse(
                {
                    "id": sid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_id,
                    "choices": [
                        {"index": 0, "delta": {}, "finish_reason": "stop"}
                    ],
                }
            )
            yield "data: [DONE]\n\n"

            fam = _family_for(e_action_final, int(e_reds_final or 0))
            inc_decision_family(fam)
            # ORDER: (family, tenant, bot)
            inc_decision_family_tenant_bot(fam, tenant_id, bot_id)
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
                        "status_code": 200,
                        "redaction_count": int(e_reds_final or 0),
                        "hash_fingerprint": content_fingerprint(accum_raw),
                        "payload_bytes": int(_blen(accum_raw)),
                        "sanitized_bytes": int(_blen(last_sanitized)),
                        "meta": {
                            "provider": model_meta,
                            "client": get_client_meta(request),
                        },
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
        }
        return StreamingResponse(gen(), headers=headers)

    # ---------- Non-streaming path ----------
    client = get_client()
    model_text, model_meta = client.chat(
        [m.model_dump() for m in body.messages], body.model
    )

    payload, _ = egress_check(model_text, debug=want_debug)
    e_action = str(payload.get("action", "allow"))
    e_text = str(payload.get("text", ""))
    e_reds = int(payload.get("redactions") or 0)
    e_hits = list(payload.get("rule_hits") or []) or None

    e_family = _family_for(e_action, e_reds)
    inc_decision_family(e_family)
    # ORDER: (family, tenant, bot)
    inc_decision_family_tenant_bot(e_family, tenant_id, bot_id)

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
                    "client": get_client_meta(request),
                },
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

    return oai_resp


# --- Images (OpenAI-compatible) ----------------------------------------------

_PLACEHOLDER_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAA"
    "AASUVORK5CYII="
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
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
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

    allowed, retry_after, _ = quota_check_and_consume(
        request, tenant_id, bot_id
    )
    if not allowed:
        inc_quota_reject_tenant_bot(tenant_id, bot_id)
        try:
            emit_audit_event(
                {
                    "ts": None,
                    "tenant_id": tenant_id,
                    "bot_id": bot_id,
                    "request_id": req_id,
                    "direction": "ingress",
                    "decision": "deny",
                    "rule_hits": None,
                    "policy_version": policy_version,
                    "status_code": 429,
                    "redaction_count": 0,
                    "hash_fingerprint": content_fingerprint("quota"),
                    "payload_bytes": 0,
                    "sanitized_bytes": 0,
                    "meta": {
                        "endpoint": "images/generations",
                        "client": get_client_meta(request),
                    },
                }
            )
        except Exception:
            pass
        headers = {
            "Retry-After": str(retry_after),
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": "deny",
            "X-Guardrail-Egress-Action": "skipped",
        }
        detail = {
            "code": "rate_limited",
            "detail": "Per-tenant quota exceeded",
            "retry_after": int(retry_after),
            "request_id": req_id,
        }
        raise HTTPException(status_code=429, detail=detail, headers=headers)

    # Ingress guard
    sanitized, families, redaction_count, _ = sanitize_text(
        body.prompt, debug=want_debug
    )
    if threat_feed_enabled():
        dyn_text, dyn_fams, dyn_reds, _ = apply_dynamic_redactions(
            sanitized, debug=want_debug
        )
    ...
