from __future__ import annotations

import base64
import os
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.middleware.request_id import get_request_id
from app.observability.metrics import retention_deleted_total, retention_preview_total
from app.routes.admin_mitigation import require_csrf
from app.security.rbac import require_operator, require_viewer
from app.services import retention as retention_service
from app.services.audit import emit_audit_event

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
    _: dict[str, Any] = Depends(require_viewer),
) -> PreviewResp:
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


def _resolve_actor(request: Request) -> str:
    for header in ("X-Admin-Actor", "X-Admin-User", "X-User"):
        value = request.headers.get(header)
        if isinstance(value, str) and value.strip():
            return value.strip()
    cookie_actor = request.cookies.get("admin_actor")
    if isinstance(cookie_actor, str) and cookie_actor.strip():
        return cookie_actor.strip()
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username = decoded.split(":", 1)[0]
            if username:
                return username
        except Exception:  # pragma: no cover - defensive parsing
            pass
    env_user = os.getenv("ADMIN_UI_USER")
    if env_user:
        return env_user
    return "admin-ui"


def _ensure_csrf_token(token: Optional[str]) -> None:
    if token and token.strip():
        return
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required")


@router.post("/retention/execute", response_model=ExecuteResp)
def retention_execute(
    payload: ExecuteReq,
    request: Request,
    _: dict[str, Any] = Depends(require_operator),
    __: None = Depends(require_csrf),
) -> ExecuteResp:
    if payload.confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Confirmation phrase mismatch")
    _ensure_csrf_token(payload.csrf_token)

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
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - backend failure surfaced
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        retention_deleted_total.labels(kind="decisions").inc(int(deleted_decisions))
        retention_deleted_total.labels(kind="adjudications").inc(int(deleted_adjudications))
    except Exception:  # pragma: no cover - metrics optional
        pass

    actor = _resolve_actor(request)
    request_id = get_request_id() or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    event = {
        "action": "admin.retention.execute",
        "actor": actor,
        "request_id": request_id,
        "before_ts_ms": int(payload.before_ts_ms),
        "tenant": payload.tenant,
        "bot": payload.bot,
        "deleted_decisions": int(deleted_decisions),
        "deleted_adjudications": int(deleted_adjudications),
    }
    try:
        emit_audit_event(event)
    except Exception:  # pragma: no cover - audit is best-effort
        pass

    return ExecuteResp(
        deleted={
            "decisions": int(deleted_decisions),
            "adjudications": int(deleted_adjudications),
        }
    )
