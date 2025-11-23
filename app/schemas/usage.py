from __future__ import annotations

from datetime import datetime
from typing import Optional

from app.pydantic_base import AppBaseModel


class UsageRow(AppBaseModel):
    tenant_id: str
    environment: str
    decision: str  # "allow" | "block" | "clarify"
    count: int


class UsageSummary(AppBaseModel):
    tenant_id: str
    environment: str
    total: int
    allow: int
    block: int
    clarify: int
    total_tokens: int = 0
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


__all__ = ["UsageRow", "UsageSummary"]
