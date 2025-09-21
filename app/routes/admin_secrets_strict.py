from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.observability.admin_audit import record
from app.observability.metrics import admin_audit_total, secrets_strict_toggle_total
from app.routes import admin_mitigation
from app.security.rbac import require_operator, require_viewer
from app.services import secrets_strict as secrets_service

router = APIRouter(prefix="/admin/api", tags=["admin-secrets"])


class StrictResp(BaseModel):
    enabled: bool


@router.get("/secrets/strict", response_model=StrictResp)
def get_strict(
    tenant: str = Query(...),
    bot: str = Query(...),
    _session: dict[str, Any] = Depends(require_viewer),
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
    user: Dict[str, Any] = Depends(require_operator),
    _csrf: None = Depends(admin_mitigation.require_csrf),
) -> OkResp:
    actor_email = (user or {}).get("email") if isinstance(user, dict) else None
    actor_role = (user or {}).get("role") if isinstance(user, dict) else None
    try:
        secrets_service.set_enabled(req.tenant, req.bot, req.enabled)
        secrets_strict_toggle_total.labels("enable" if req.enabled else "disable").inc()
    except HTTPException as exc:
        try:
            admin_audit_total.labels("secrets_strict_set", "error").inc()
        except Exception:
            pass
        record(
            action="secrets_strict_set",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=req.tenant,
            bot=req.bot,
            outcome="error",
            meta={"error": exc.detail, "enabled": bool(req.enabled)},
        )
        raise
    except Exception as exc:
        try:
            admin_audit_total.labels("secrets_strict_set", "error").inc()
        except Exception:
            pass
        record(
            action="secrets_strict_set",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=req.tenant,
            bot=req.bot,
            outcome="error",
            meta={"error": str(exc), "enabled": bool(req.enabled)},
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    try:
        admin_audit_total.labels("secrets_strict_set", "ok").inc()
    except Exception:
        pass
    record(
        action="secrets_strict_set",
        actor_email=actor_email,
        actor_role=actor_role,
        tenant=req.tenant,
        bot=req.bot,
        outcome="ok",
        meta={"enabled": bool(req.enabled)},
    )
    return OkResp(ok=True)
