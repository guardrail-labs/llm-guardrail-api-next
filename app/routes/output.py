from __future__ import annotations

import os
import uuid
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.routes.schema import OutputGuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply, current_rules_version
from app.config import get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


@router.post("/output", response_model=GuardrailResponse)
def guard_output(
    ingress: OutputGuardrailRequest, s=Depends(get_settings)
) -> GuardrailResponse:
    """
    Egress filter:
      - Enforces output size limit via OUTPUT_MAX_CHARS (env) or settings.MAX_OUTPUT_CHARS.
      - If REDACT_SECRETS=true, apply policy redactions.
      - Always return decision="allow" with required schema fields.
    """
    req_id = getattr(ingress, "request_id", None) or str(uuid.uuid4())

    # Env has priority; fall back to settings to preserve existing config path
    max_chars_env = _env_int("OUTPUT_MAX_CHARS", 0)
    max_chars_cfg = int(getattr(s, "MAX_OUTPUT_CHARS", 0) or 0)
    max_chars = max(max_chars_env, max_chars_cfg)

    if max_chars and len(ingress.output) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Output too large",
        )

    redact = (os.environ.get("REDACT_SECRETS") or "false").lower() == "true"

    transformed: str
    rule_hits: List[Dict[str, Any]]
    reason: str

    if redact:
        res = evaluate_and_apply(ingress.output)
        transformed = res.get("transformed_text", ingress.output)
        rule_hits = list(res.get("rule_hits", []))
        reason = "redacted" if int(res.get("redactions", 0) or 0) > 0 else ""
    else:
        transformed = ingress.output
        rule_hits = []
        reason = ""

    return GuardrailResponse(
        transformed_text=transformed,
        decision="allow",
        request_id=req_id,
        reason=reason,
        rule_hits=rule_hits,
        policy_version=current_rules_version(),
    )
