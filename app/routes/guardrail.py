from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi import HTTPException, status

from app.routes.schema import GuardrailRequest, GuardrailResponse  # keep your existing schema path
from app.services.policy import evaluate_and_apply
from app.config import get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])


@router.post("", response_model=GuardrailResponse)
def guard(ingress: GuardrailRequest, s=Depends(get_settings)) -> GuardrailResponse:
    # MAX_PROMPT_CHARS enforcement (413) happens at the route boundary
    max_chars = int(getattr(s, "MAX_PROMPT_CHARS", 0) or 0)
    if max_chars and len(ingress.prompt) > max_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Prompt too large",
        )

    payload = evaluate_and_apply(ingress.prompt)
    # Satisfy mypy: return the annotated model, not a raw dict
    return GuardrailResponse(**payload)
