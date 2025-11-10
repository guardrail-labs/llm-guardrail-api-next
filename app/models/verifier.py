from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VerifierInput(BaseModel):
    text: str
    modality: str = "text"
    rule_hits: Dict[str, Any] = Field(default_factory=dict)
    context: Optional[dict] = None


class VerifierResult(BaseModel):
    decision: str  # block|clarify|allow
    categories: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    latency_ms: Optional[int] = None
    provider: Optional[str] = None
