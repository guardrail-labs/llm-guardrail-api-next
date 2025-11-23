from __future__ import annotations

from pydantic import BaseModel


class UsageRow(BaseModel):
    tenant_id: str
    environment: str
    decision: str  # "allow" | "block" | "clarify"
    count: int


class UsageSummary(BaseModel):
    tenant_id: str
    environment: str
    total: int
    allow: int
    block: int
    clarify: int
