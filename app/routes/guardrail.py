import os

from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth import require_api_key
from app.schemas import ErrorResponse, GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply


router = APIRouter(dependencies=[Depends(require_api_key)])


def _resolve_max_chars() -> int:
    """Prefer live env (so tests/runtime overrides work); fallback to a safe default."""
    v = os.environ.get("MAX_PROMPT_CHARS")
    if v is not None:
        try:
            return int(v)
        except ValueError:
            pass
    return 16000


def _check_size(ingress: GuardrailRequest) -> None:
    max_chars = _resolve_max_chars()
    if len(ingress.prompt) > max_chars:
        raise HTTPException(
            status_code=413,
            detail=f"Prompt too large (max {max_chars} chars)",
        )


@router.post(
    "/guardrail",
    response_model=GuardrailResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        413: {"model": ErrorResponse, "description": "Payload too large"},
        500: {"model": ErrorResponse, "description": "Server misconfiguration"},
    },
    summary="Evaluate a prompt against guardrail rules",
    dependencies=[Depends(_check_size)],
)
def guard(ingress: GuardrailRequest) -> GuardrailResponse:
    # Size already validated by dependency.
    return evaluate_and_apply(ingress.prompt)
