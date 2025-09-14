from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from app.services.egress.incidents import list_incidents

router = APIRouter(prefix="/admin/api/egress", tags=["admin-egress"])

@router.get("/incidents")
def get_egress_incidents(
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    return {"items": list_incidents(tenant=tenant, bot=bot, limit=limit)}
