from __future__ import annotations

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.routes import admin_mitigation
from app.security.rbac import require_operator, require_viewer
from app.services import mitigation_store as MS

router = APIRouter(prefix="/admin/api", tags=["admin-mitigation"])


class ModeResp(BaseModel):
    mode: Optional[str]
    source: str  # "explicit" | "default"


@router.get("/mitigation-mode", response_model=ModeResp)
def get_mode(
    tenant: str = Query(...),
    bot: str = Query(...),
    _session: dict[str, Any] = Depends(require_viewer),
) -> ModeResp:
    mode = MS.get_mode(tenant, bot)
    return ModeResp(mode=mode, source="explicit" if mode else "default")


class PutReq(BaseModel):
    tenant: str
    bot: str
    mode: str
    csrf_token: Optional[str] = None


class OkResp(BaseModel):
    ok: bool


@router.put("/mitigation-mode", response_model=OkResp)
def put_mode(
    req: PutReq,
    _session: dict[str, Any] = Depends(require_operator),
    _csrf: None = Depends(admin_mitigation.require_csrf),
) -> OkResp:
    try:
        MS.set_mode(req.tenant, req.bot, req.mode)
        return OkResp(ok=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ListEntry(BaseModel):
    tenant: str
    bot: str
    mode: str


@router.get("/mitigation-modes", response_model=List[ListEntry])
def list_modes(
    _session: dict[str, Any] = Depends(require_viewer),
) -> List[ListEntry]:
    return [ListEntry(**entry) for entry in MS.list_modes()]

