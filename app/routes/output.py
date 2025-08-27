from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi import HTTPException, status

from app.routes.schema import OutputGuardrailRequest, GuardrailResponse  # keep your existing schema path
from app.services.policy import evaluate_and_apply
from app.config import get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


@router.post("/output", response_model=GuardrailResponse)
def guard_output(ingress: OutputGuardrailRequest, s=Depends(get_settings)) -> GuardrailResponse:
    # MAX_OUTPUT_CHARS enforcement (413) happens at the route boundary
    max_chars = int(getattr(s, "MAX_OUTPUT_CHARS", 0) or 0)
    if max_chars and len(ingress.output) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Output too large",
        )

    payload = evaluate_and_apply(ingress.output)
    return GuardrailResponse(**payload)
