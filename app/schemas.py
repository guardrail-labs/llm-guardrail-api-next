from typing import Optional

from pydantic import BaseModel


class GuardrailRequest(BaseModel):
    prompt: str


class GuardrailOutputRequest(BaseModel):
    output: str
    source_request_id: Optional[str] = None


class GuardrailResponse(BaseModel):
    request_id: str
    decision: str
    reason: str
    rule_hits: list[str]
    transformed_text: str
    policy_version: str


class ErrorResponse(BaseModel):
    detail: str
