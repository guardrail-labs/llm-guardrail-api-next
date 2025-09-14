from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

from app.services.egress.incidents import list_incidents

router = APIRouter()


def _require_admin_key(x_admin_key: Optional[str]) -> None:
    required = os.getenv("ADMIN_API_KEY")
    if required and (not x_admin_key or x_admin_key != required):
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/admin/api/egress/incidents")
async def get_egress_incidents(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
) -> dict:
    _require_admin_key(x_admin_key)
    return {"incidents": list_incidents()}
