from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.observability.metrics import secrets_strict_toggle_total
from app.routes import admin_mitigation
from app.services import secrets_strict as secrets_service

router = APIRouter(prefix="/admin/api", tags=["admin-secrets"])


class StrictResp(BaseModel):
    enabled: bool


@router.get("/secrets/strict", response_model=StrictResp)
def get_strict(
    tenant: str = Query(...),
    bot: str = Query(...),
    _session: None = Depends(admin_mitigation.require_admin_session),
) -> StrictResp:
    return StrictResp(enabled=secrets_service.is_enabled(tenant, bot))


class StrictSetReq(BaseModel):
    tenant: str
    bot: str
    enabled: bool
    csrf_token: Optional[str] = None


class OkResp(BaseModel):
    ok: bool


@router.put("/secrets/strict", response_model=OkResp)
def set_strict(
    req: StrictSetReq,
    _session: None = Depends(admin_mitigation.require_admin_session),
    _csrf: None = Depends(admin_mitigation.require_csrf),
) -> OkResp:
    try:
        secrets_service.set_enabled(req.tenant, req.bot, req.enabled)
        secrets_strict_toggle_total.labels("enable" if req.enabled else "disable").inc()
        return OkResp(ok=True)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
