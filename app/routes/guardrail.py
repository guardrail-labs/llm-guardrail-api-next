from fastapi import APIRouter, Depends, HTTPException

from app.config import Settings
from app.middleware.auth import require_api_key
from app.schemas import ErrorResponse, GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.post(
    "/guardrail",
    response_model=GuardrailResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        413: {"model": ErrorResponse, "description": "Payload too large"},
        500: {"model": ErrorResponse, "description": "Server misconfiguration"},
    },
    summary="Evaluate a prompt against guardrail rules",
)
def guard(ingress: GuardrailRequest) -> GuardrailResponse:
    # Read env-driven settings per request so tests (and runtime) can override via env
    s = Settings()
    max_chars = int(s.MAX_PROMPT_CHARS)
    if len(ingress.prompt) > max_chars:
        raise HTTPException(
            status_code=413,
            detail=f"Prompt too large (max {max_chars} chars)",
        )

    outcome = evaluate_and_apply(ingress.prompt)
    return outcome
