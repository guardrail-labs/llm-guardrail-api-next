import os

from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth import require_api_key
from app.schemas import ErrorResponse, GuardrailOutputRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply

router = APIRouter(dependencies=[Depends(require_api_key)])


def _resolve_max_output_chars() -> int:
    v = os.environ.get("MAX_OUTPUT_CHARS")
    if v is not None:
        try:
            return int(v)
        except ValueError:
            pass
    return 16000  # default


def _check_size(ingress: GuardrailOutputRequest) -> None:
    max_chars = _resolve_max_output_chars()
    if len(ingress.output) > max_chars:
        raise HTTPException(
            status_code=413,
            detail=f"Output too large (max {max_chars} chars)",
        )


@router.post(
    "/guardrail/output",
    response_model=GuardrailResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        413: {"model": ErrorResponse, "description": "Payload too large"},
        500: {"model": ErrorResponse, "description": "Server misconfiguration"},
    },
    summary="Evaluate a model output against guardrail rules",
    dependencies=[Depends(_check_size)],
)
def guard_output(ingress: GuardrailOutputRequest) -> GuardrailResponse:
    return evaluate_and_apply(ingress.output)
