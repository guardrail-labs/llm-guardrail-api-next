from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Header, Response
from pydantic import BaseModel

from app.observability.metrics import inc_egress_redactions
from app.services.egress.incidents import record_incident
from app.services.egress.sanitizer import sanitize
from app.shared.headers import attach_guardrail_headers

router = APIRouter(prefix="/guardrail", tags=["guardrail-egress"])

class SanitizeIn(BaseModel):
    text: str
    tenant: Optional[str] = "acme"
    bot: Optional[str] = "chatbot-a"

class SanitizeOut(BaseModel):
    text: str
    redactions: int
    reasons: List[str]

@router.post("/sanitize", response_model=SanitizeOut)
def post_sanitize(
    payload: SanitizeIn,
    response: Response,
    x_debug: Optional[str] = Header(default=None),
):
    res = sanitize(payload.text)
    tenant = payload.tenant or "default"
    bot = payload.bot or "default"

    if res.count > 0:
        for r in (res.reasons or ["unspecified"]):
            inc_egress_redactions(tenant, bot, r, n=1)
        record_incident(tenant, bot, res.count, res.reasons)
        attach_guardrail_headers(
            response,
            policy_version=None,
            decision="allow",
            ingress_action=None,
            egress_action="redact",
            redaction_count=res.count,
            redaction_reasons=res.reasons,
        )
    else:
        attach_guardrail_headers(
            response, decision="allow", egress_action="allow", redaction_count=0
        )

    return SanitizeOut(text=res.text, redactions=res.count, reasons=res.reasons)
