from __future__ import annotations

from typing import List

from pydantic import BaseModel


class GuardrailRequest(BaseModel):
    prompt: str


class OutputGuardrailRequest(BaseModel):
    output: str


class GuardrailResponse(BaseModel):
    request_id: str
    decision: str
    reason: str
    rule_hits: List[str]
    policy_version: str
    transformed_text: str
