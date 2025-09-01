from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import get_settings
from app.routes.schema import GuardrailResponse, OutputGuardrailRequest
from app.services.policy import current_rules_version, evaluate_and_apply
from app.services.audit_forwarder import emit_event as emit_audit_event
from app.services.verifier import content_fingerprint
from app.telemetry.metrics import (
    inc_decision_family,
    inc_decision_family_tenant_bot,
)
from app.shared.headers import TENANT_HEADER, BOT_HEADER

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _flatten_rule_hits(as_dicts: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for h in as_dicts:
        pat = h.get("pattern")
        tag = h.get("tag")
        if isinstance(pat, str) and pat:
            if isinstance(tag, str) and tag:
                out.append(f"{tag}:{pat}")
            else:
                out.append(pat)
    return out


def _blen(s: str) -> int:
    return len((s or "").encode("utf-8"))


@router.post("/output", response_model=GuardrailResponse)
def guard_output(
    ingress: OutputGuardrailRequest,
    request: Request,
    s=Depends(get_settings),
) -> GuardrailResponse:
    """
    Egress filter:
      - Enforce output size limit via OUTPUT_MAX_CHARS or settings.MAX_OUTPUT_CHARS.
      - If REDACT_SECRETS=true, apply policy redactions.
      - Always return decision="allow" with required schema fields.
      - Emit enriched enterprise audit + family metrics.
    """
    # request/tenancy context
    req_id = (
        getattr(ingress, "request_id", None)
        or request.headers.get("X-Request-ID")
        or str(uuid.uuid4())
    )
    tenant_id = request.headers.get(TENANT_HEADER) or "default"
    bot_id = request.headers.get(BOT_HEADER) or "default"

    # limits
    max_chars_env = _env_int("OUTPUT_MAX_CHARS", 0)
    max_chars_cfg = int(getattr(s, "MAX_OUTPUT_CHARS", 0) or 0)
    max_chars = max(max_chars_env, max_chars_cfg)

    if max_chars and len(ingress.output) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Output too large",
        )

    # redact flag
    redact = (os.environ.get("REDACT_SECRETS") or "false").lower() == "true"

    transformed: str
    rule_hits_strs: List[str]
    redactions = 0

    if redact:
        # Use ingress policy helpers for consistent redactions.
        res = evaluate_and_apply(ingress.output)
        transformed = res.get("transformed_text", ingress.output)
        rule_hits_strs = _flatten_rule_hits(list(res.get("rule_hits", [])))
        redactions = int(res.get("redactions", 0) or 0)
    else:
        transformed = ingress.output
        rule_hits_strs = []

    # decision family for metrics
    family = "sanitize" if redactions > 0 else "allow"

    # metrics
    inc_decision_family(family)
    inc_decision_family_tenant_bot(tenant_id, bot_id, family)

    # enriched audit payload
    try:
        emit_event = {
            "ts": None,
            "tenant_id": tenant_id,
            "bot_id": bot_id,
            "request_id": req_id,
            "direction": "egress",
            "decision": "allow",
            "rule_hits": (rule_hits_strs or None),
            "policy_version": current_rules_version(),
            "verifier_provider": None,
            "fallback_used": None,
            "status_code": 200,
            "redaction_count": redactions,
            "hash_fingerprint": content_fingerprint(ingress.output or ""),
            "payload_bytes": int(_blen(ingress.output)),
            "sanitized_bytes": int(_blen(transformed)),
            "meta": {},
        }
        emit_audit_event(emit_event)
    except Exception:
        # best-effort audit; never break egress on logging errors
        pass

    # API contract: always allow; include reason only when redactions occurred
    reason = "redacted" if redactions > 0 else ""

    return GuardrailResponse(
        transformed_text=transformed,
        decision="allow",
        request_id=req_id,
        reason=reason,
        rule_hits=rule_hits_strs,
        policy_version=current_rules_version(),
    )

