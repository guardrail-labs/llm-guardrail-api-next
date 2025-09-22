from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.observability.admin_audit import record
from app.observability.metrics import (
    admin_audit_total,
    retention_deleted_total,
    retention_preview_total,
)
from app.routes.admin_mitigation import require_csrf
from app.security.rbac import RBACError, ensure_scope, require_operator, require_viewer
from app.services import retention as retention_service

router = APIRouter(prefix="/admin/api", tags=["admin-retention"])

_MAX_BATCH = 50_000


class PreviewReq(BaseModel):
    before_ts_ms: int = Field(
        ..., description="Delete anything earlier than this epoch ms (exclusive)"
    )
    tenant: Optional[str] = None
    bot: Optional[str] = None


class PreviewResp(BaseModel):
    before_ts_ms: int
    decisions: Dict[str, int]
    adjudications: Dict[str, int]


@router.post("/retention/preview", response_model=PreviewResp)
def retention_preview(
    payload: PreviewReq,
    user: Dict[str, Any] = Depends(require_viewer),
) -> PreviewResp:
    try:
        ensure_scope(user, tenant=payload.tenant, bot=payload.bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    decisions = retention_service.count_decisions_before(
        payload.before_ts_ms,
        tenant=payload.tenant,
        bot=payload.bot,
    )
    adjudications = retention_service.count_adjudications_before(
        payload.before_ts_ms,
        tenant=payload.tenant,
        bot=payload.bot,
    )
    try:  # metrics are optional in some environments
        retention_preview_total.inc()
    except Exception:  # pragma: no cover - defensive metrics guard
        pass
    return PreviewResp(
        before_ts_ms=payload.before_ts_ms,
        decisions={"count": int(decisions)},
        adjudications={"count": int(adjudications)},
    )


class ExecuteReq(PreviewReq):
    confirm: str = Field(..., description='Must be exactly "DELETE" to proceed')
    csrf_token: Optional[str] = None
    max_delete: int = Field(
        _MAX_BATCH,
        ge=1,
        le=_MAX_BATCH,
        description="Upper bound on total records removed this request",
    )


class ExecuteResp(BaseModel):
    deleted: Dict[str, int]


def _ensure_csrf_token(token: Optional[str]) -> None:
    if token and token.strip():
        return
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required")


@router.post("/retention/execute", response_model=ExecuteResp)
def retention_execute(
    payload: ExecuteReq,
    user: Dict[str, Any] = Depends(require_operator),
    __: None = Depends(require_csrf),
) -> ExecuteResp:
    actor_email = (user or {}).get("email") if isinstance(user, dict) else None
    actor_role = (user or {}).get("role") if isinstance(user, dict) else None
    tenant = payload.tenant
    bot = payload.bot
    try:
        ensure_scope(user, tenant=tenant, bot=bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if payload.confirm != "DELETE":
        try:
            admin_audit_total.labels("retention_execute", "error").inc()
        except Exception:
            pass
        record(
            action="retention_execute",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"reason": "confirm_mismatch", "before_ts_ms": int(payload.before_ts_ms)},
        )
        raise HTTPException(status_code=400, detail="Confirmation phrase mismatch")
    try:
        _ensure_csrf_token(payload.csrf_token)
    except HTTPException as exc:
        try:
            admin_audit_total.labels("retention_execute", "error").inc()
        except Exception:
            pass
        record(
            action="retention_execute",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"reason": "csrf_required", "before_ts_ms": int(payload.before_ts_ms)},
        )
        raise exc

    try:
        deleted_decisions = retention_service.delete_decisions_before(
            payload.before_ts_ms,
            tenant=payload.tenant,
            bot=payload.bot,
            limit=payload.max_delete,
        )
        remaining = max(payload.max_delete - int(deleted_decisions), 0)
        deleted_adjudications = retention_service.delete_adjudications_before(
            payload.before_ts_ms,
            tenant=payload.tenant,
            bot=payload.bot,
            limit=remaining,
        )
    except HTTPException as exc:
        try:
            admin_audit_total.labels("retention_execute", "error").inc()
        except Exception:
            pass
        record(
            action="retention_execute",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"before_ts_ms": int(payload.before_ts_ms), "error": exc.detail},
        )
        raise
    except Exception as exc:  # pragma: no cover - backend failure surfaced
        try:
            admin_audit_total.labels("retention_execute", "error").inc()
        except Exception:
            pass
        record(
            action="retention_execute",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"before_ts_ms": int(payload.before_ts_ms), "error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        retention_deleted_total.labels(kind="decisions").inc(int(deleted_decisions))
        retention_deleted_total.labels(kind="adjudications").inc(int(deleted_adjudications))
    except Exception:  # pragma: no cover - metrics optional
        pass

    try:
        admin_audit_total.labels("retention_execute", "ok").inc()
    except Exception:
        pass
    record(
        action="retention_execute",
        actor_email=actor_email,
        actor_role=actor_role,
        tenant=tenant,
        bot=bot,
        outcome="ok",
        meta={
            "before_ts_ms": int(payload.before_ts_ms),
            "deleted_decisions": int(deleted_decisions),
            "deleted_adjudications": int(deleted_adjudications),
        },
    )

    return ExecuteResp(
        deleted={
            "decisions": int(deleted_decisions),
            "adjudications": int(deleted_adjudications),
        }
    )
