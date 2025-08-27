from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    ok: bool
    status: str
    requests_total: float
    decisions_total: float
    rules_version: str

class EvaluateRequest(BaseModel):
    text: str
    request_id: Optional[str] = None

class Decision(BaseModel):
    type: str
    changed: Optional[bool] = None
    info: Optional[Dict[str, Any]] = None

class EvaluateResponse(BaseModel):
    request_id: str
    action: str
    transformed_text: str
    decisions: List[Decision] = Field(default_factory=list)

class AdminReloadResponse(BaseModel):
    reloaded: bool
    version: str
    rules_loaded: int
