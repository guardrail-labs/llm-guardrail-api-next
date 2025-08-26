from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.middleware.auth import require_api_key
from app.services.policy import evaluate_and_apply

router = APIRouter(dependencies=[Depends(require_api_key)])


class GuardrailRequest(BaseModel):
    prompt: str
    context: dict | None = None


class GuardrailResponse(BaseModel):
    request_id: str
    decision: str
    reason: str
    rule_hits: list[str]
    transformed_text: str
    policy_version: str


@router.post("/guardrail", response_model=GuardrailResponse)
def guard(ingress: GuardrailRequest):
    outcome = evaluate_and_apply(ingress.prompt)
    return outcome
