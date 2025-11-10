# app/models/verifier.py
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class VerifierInput(BaseModel):
    text: str
    modality: str = "text"
    rule_hits: dict[str, object] = Field(default_factory=dict)
    context: Optional[dict[str, object]] = None


class VerifierResult(BaseModel):
    # one of: "block" | "clarify" | "allow"
    decision: str
    categories: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    latency_ms: Optional[int] = None
    provider: Optional[str] = None
