from fastapi import APIRouter, Depends

from app.middleware.auth import require_api_key
from app.schemas import ErrorResponse, GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.post(
    
    "/guardrail",
    response_model=GuardrailResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        500: {"model": ErrorResponse, "description": "Server misconfiguration"},
    },
    summary="Evaluate a prompt against guardrail rules",
    description=(
        "Runs lightweight detectors for prompt injection, secrets, and long encoded "
        "blobs. Returns a decision (allow|block), matched rule IDs, and the policy version."
    ),
)
def guard(ingress: GuardrailRequest) -> GuardrailResponse:
    outcome = evaluate_and_apply(ingress.prompt)
    return outcome
