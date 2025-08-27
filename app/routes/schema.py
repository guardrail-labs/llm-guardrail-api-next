from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field


class GuardrailRequest(BaseModel):
    text: str = Field(alias="prompt")
    request_id: str | None = None
    model_config = ConfigDict(populate_by_name=True)

    @property
    def prompt(self) -> str:  # backwards compat
        return self.text


class OutputGuardrailRequest(BaseModel):
    output: str


class GuardrailResponse(BaseModel):
    request_id: str
    decision: str
    reason: str
    rule_hits: List[str]
    policy_version: str
    transformed_text: str
