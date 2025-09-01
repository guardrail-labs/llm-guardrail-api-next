# file: app/routes/openai_compat.py
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.services.policy import (
    _normalize_family,
    current_rules_version,
    sanitize_text,
)
from app.services.detectors import evaluate_prompt
from app.services.threat_feed import (
    apply_dynamic_redactions,
    threat_feed_enabled,
)
from app.services.egress import egress_check
from app.services.verifier import content_fingerprint
from app.services.llm_client import get_client
from app.services.audit_forwarder import emit_event as emit_audit_event
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
)
from app.shared.headers import TENANT_HEADER, BOT_HEADER


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
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
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
        model_text, model_meta = client.chat(
            [m.model_dump() for m in body.messages], body.model
        )

        # Egress (once)
        payload, _ = egress_check(model_text, debug=want_debug)
        e_action = str(payload.get("action", "allow"))
        if e_action == "deny":
            err_body = _oai_error("Response denied by guardrail policy")
            headers = {
                "X-Guardrail-Policy-Version": policy_version,
                "X-Guardrail-Ingress-Action": ingress_action,
                "X-Guardrail-Egress-Action": e_action,
            }
            raise HTTPException(status_code=400, detail=err_body, headers=headers)

        e_text = str(payload.get("text", ""))
        e_reds = int(payload.get("redactions") or 0)
        e_hits = list(payload.get("rule_hits") or []) or None

        e_family = _family_for(e_action, e_reds)
        inc_decision_family(e_family)
        inc_decision_family_tenant_bot(tenant_id, bot_id, e_family)

        # Audit egress (full text)
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

        sid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created = now_ts
        model_id = body.model

        def gen() -> Iterable[str]:
            # First chunk announces role
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
            # Content chunks
            for piece in _chunk_text(e_text, max_len=60):
                yield _sse(
                    {
                        "id": sid,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model_id,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": piece},
                                "finish_reason": None,
                            }
                        ],
                    }
                )
            # Final chunk with finish_reason=stop
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

        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": e_action,
            "X-Guardrail-Egress-Redactions": str(e_reds),
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
