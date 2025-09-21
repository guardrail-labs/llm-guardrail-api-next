from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.observability import admin_audit as AA
from app.security.rbac import require_viewer

router = APIRouter(prefix="/admin/api", tags=["admin-audit"])


class AuditItem(BaseModel):
    ts_ms: int
    action: str
    actor_email: Optional[str]
    actor_role: Optional[str]
    tenant: Optional[str]
    bot: Optional[str]
    outcome: str
    meta: Dict[str, Any]


@router.get("/audit/recent", response_model=List[AuditItem])
def recent_audit(
    limit: int = Query(20, ge=1, le=200),
    _: Dict[str, Any] = Depends(require_viewer),
) -> List[AuditItem]:
    return [AuditItem(**item) for item in AA.recent(limit)]
