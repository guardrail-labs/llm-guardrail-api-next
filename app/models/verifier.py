# app/models/verifier.py
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


Decision = Literal["block", "clarify", "allow"]


class VerifierInput(BaseModel):
    text: str
    modality: str = "text"
    # Map of rule identifier -> arbitrary metadata (e.g., counts, weights)
    rule_hits: Dict[str, Any] = Field(default_factory=dict)
    context: Optional[Dict[str, Any]] = None


class VerifierResult(BaseModel):
    decision: Decision  # block|clarify|allow
    categories: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    latency_ms: Optional[int] = None
    provider: Optional[str] = None
