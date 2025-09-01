from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, Request
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

router = APIRouter(prefix="/proxy", tags=["proxy"])


# ---------------------------
# Models
# ---------------------------

class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    request_id: Optional[str] = None


class ChatItem(BaseModel):
    role: str
    content: str


class IngressDecision(BaseModel):
    action: str
    text: str
    transformed_text: str
    risk_score: int
    rule_hits: Optional[List[str]] = None
    redactions: Optional[int] = None


class EgressDecision(BaseModel):
    action: str
    text: str
    rule_hits: Optional[List[str]] = None
    redactions: Optional[int] = None


class ChatResponse(BaseModel):
    request_id: str
    policy_version: str
    model: Dict[str, str]
    ingress: IngressDecision
    output_text: str
    egress: EgressDecision


# ---------------------------
# Helpers
# ---------------------------

def _tenant_bot_from_headers(request: Request) -> Tuple[str, str]:
    tenant = request.headers.get(TENANT_HEADER) or "default"
    bot = request.headers.get(BOT_HEADER) or "default"
    return tenant, bot


def _blen(s: Optional[str]) -> int:
    return len((s or "").encode("utf-8"))


def _normalize_rule_hits(raw_hits: List[Any], raw_decisions: List[Any]) -> List[str]:
    """
    Same normalization used elsewhere: flatten to 'source:list:id' strings.
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


def _family_for(action: str, redactions: int) -> str:
    if action == "deny":
        return "block"
    if redactions > 0:
        return "sanitize"
    return "allow"


# ---------------------------
# Route
# ---------------------------

@router.post("/chat", response_model=ChatResponse)
async def proxy_chat(
    request: Request,
    body: ChatRequest,
    x_debug: Optional[str] = Header(
        default=None, alias="X-Debug", convert_underscores=False
    ),
) -> ChatResponse:
    """
    End-to-end guarded chat:
      1) Ingress sanitize + detect
      2) If not denied, call provider (default: local echo)
      3) Egress sanitize/deny
      4) Emit enriched audit + metrics at each step
    """
    want_debug = x_debug == "1"
    tenant_id, bot_id = _tenant_bot_from_headers(request)
    policy_version = current_rules_version()

    req_id = body.request_id or request.headers.get("X-Request-ID") or str(uuid.uuid4())

    # -------- Ingress phase --------
    # Join all messages for scanning (conservative).
    joined = "\n".join(f"{m.role}: {m.content}" for m in body.messages or [])

    sanitized, families, redaction_count, _dbg = sanitize_text(joined, debug=want_debug)
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
        # Block provider call outright
        return ChatResponse(
            request_id=req_id,
            policy_version=policy_version,
            model={"provider": "skipped", "model": body.model},
            ingress=IngressDecision(
                action="deny",
                text=xformed,
                transformed_text=xformed,
                risk_score=int(det.get("risk_score", 0)),
                rule_hits=(combined_hits or None),
                redactions=int(redaction_count or 0) or None,
            ),
            output_text="",
            egress=EgressDecision(action="deny", text="", rule_hits=["policy:deny:*"]),
        )

    # -------- Provider call --------
    client = get_client()
    model_text, model_meta = client.chat(
        [m.model_dump() for m in body.messages], body.model
    )

    # -------- Egress phase --------
    payload, _dbg2 = egress_check(model_text, debug=want_debug)
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

    return ChatResponse(
        request_id=req_id,
        policy_version=policy_version,
        model={"provider": str(model_meta.get("provider", "")), "model": body.model},
        ingress=IngressDecision(
            action=ingress_action,
            text=xformed,
            transformed_text=xformed,
            risk_score=int(det.get("risk_score", 0)),
            rule_hits=(combined_hits or None),
            redactions=int(redaction_count or 0) or None,
        ),
        output_text=e_text,
        egress=EgressDecision(
            action=e_action, text=e_text, rule_hits=e_hits, redactions=e_reds or None
        ),
    )
