from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

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


class AdminUsagePeriodSummary(BaseModel):
    period: str = Field(..., description="Resolved period key (e.g. '7d', '30d', 'current_month')")
    tenant: Optional[str] = Field(
        None,
        description="Optional tenant filter applied to this summary",
    )

    total: int = Field(..., ge=0)
    allow: int = Field(..., ge=0)
    block: int = Field(..., ge=0)
    clarify: int = Field(..., ge=0)
    total_tokens: int = Field(..., ge=0)

    tenant_count: int = Field(..., ge=0, description="Distinct tenant count in this period")
    environment_count: int = Field(..., ge=0, description="Distinct environment count in this period")

    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


__all__ = ["UsageRow", "UsageSummary", "AdminUsagePeriodSummary"]
