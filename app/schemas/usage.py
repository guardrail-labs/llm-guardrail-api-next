from __future__ import annotations

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


__all__ = ["UsageRow", "UsageSummary"]
