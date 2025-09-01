# file: app/routes/openai_compat.py
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request, status
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


def _compat_models() -> List[Dict[str, Any]]:
    """
    Return OpenAI-style model objects.
    Configure via OAI_COMPAT_MODELS="gpt-4o-mini,gpt-4o" or default to ["demo"].
    """
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


@router.get("/models")
async def list_models():
    """
    Minimal OpenAI-compatible /v1/models listing.
    """
    return {"object": "list", "data": _compat_models()}

class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


class ChatCompletionsRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: Optional[bool] = False  # not supported yet
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


# ---------------------------
# Route
# ---------------------------

@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    body: ChatCompletionsRequest,
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
):
    """
    OpenAI-compatible (non-streaming) chat endpoint with inline guardrails.

    Compatibility:
      - Request/response shape mirrors OpenAI /v1/chat/completions (subset).
      - Guard decisions exposed via headers; full details go to audit/metrics.
      - On ingress deny: 400 with OpenAI-style error object.
    """
    if body.stream:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_oai_error("stream=True not supported"),
        )

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
        # Strict compat: return 400 with OpenAI-style error object
        err_body = _oai_error("Request denied by guardrail policy")
        headers = {
            "X-Guardrail-Policy-Version": policy_version,
            "X-Guardrail-Ingress-Action": ingress_action,
            "X-Guardrail-Egress-Action": "skipped",
        }
        raise HTTPException(status_code=400, detail=err_body, headers=headers)

    # ---------- Provider ----------
    client = get_client()
    model_text, model_meta = client.chat(
        [m.model_dump() for m in body.messages], body.model
    )

    # ---------- Egress ----------
    payload, _ = egress_check(model_text, debug=want_debug)
    e_action = str(payload.get("action", "allow"))
    e_text = str(payload.get("text", ""))
    e_reds = int(payload.get("redactions") or 0)
    e_hits = list(payload.get("rule_hits") or []) or None

    e_family = _family_for(e_action, e_reds)
    inc_decision_family(e_family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, e_family)

    # Audit egress
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

    # OpenAI-compatible response shape (subset)
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

    # Attach guard signals via headers
    request.state._extra_headers = {
        "X-Guardrail-Policy-Version": policy_version,
        "X-Guardrail-Ingress-Action": ingress_action,
        "X-Guardrail-Egress-Action": e_action,
        "X-Guardrail-Egress-Redactions": str(e_reds),
    }

    return oai_resp
