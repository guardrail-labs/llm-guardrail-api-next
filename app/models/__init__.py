from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from .debug import DebugPayload, RedactionSpan, SourceDebug


class HealthCheckResult(BaseModel):
    status: Literal["ok", "fail"]
    detail: Optional[Any] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class HealthResponse(BaseModel):
    status: Literal["ok", "fail"]
    checks: Dict[str, HealthCheckResult]

    @property
    def ok(self) -> bool:
        return self.status == "ok"


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
    debug: Optional[DebugPayload] = None


class AdminReloadResponse(BaseModel):
    ok: bool
    version: str
    rules_count: int


__all__ = [
    "HealthCheckResult",
    "HealthResponse",
    "EvaluateRequest",
    "Decision",
    "EvaluateResponse",
    "AdminReloadResponse",
    "DebugPayload",
    "SourceDebug",
    "RedactionSpan",
]
