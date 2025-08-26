"""Shared request/response models for the API."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class GuardrailRequest(BaseModel):
    """Incoming request to evaluate text against guardrail rules."""

    prompt: str = Field(..., description="User prompt or model output to evaluate")
    context: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional context object for downstream use"
    )


class GuardrailResponse(BaseModel):
    """Decision outcome from the guardrail."""

    request_id: str = Field(..., description="Server-generated request identifier")
    decision: str = Field(..., description='One of: "allow" | "block"')
    reason: str = Field(..., description="Human-readable reason summarizing rule hits")
    rule_hits: List[str] = Field(
        default_factory=list, description="List of matched rule identifiers"
    )
    transformed_text: str = Field(
        ..., description="Returned text after any transformations (no-op today)"
    )
    policy_version: str = Field(..., description="Policy ruleset version")


class ErrorResponse(BaseModel):
    """Error payload."""

    detail: str = Field(..., description="Error detail message")
