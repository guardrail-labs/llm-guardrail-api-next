from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.observability.admin_audit import record
from app.observability.metrics import (
    admin_audit_total,
    webhook_dlq_depth,
    webhook_dlq_purge_total,
    webhook_dlq_retry_total,
)
from app.routes.admin_ui import _require_ui_csrf
from app.security.rbac import require_operator, require_viewer
from app.services import webhooks_dlq as DLQ

logger = logging.getLogger("guardrail.admin.webhooks.dlq")

router = APIRouter(prefix="/admin/api/webhooks", tags=["admin-webhooks"])


class DlqStats(BaseModel):
    size: int
    oldest_ts_ms: Optional[int] = None
    newest_ts_ms: Optional[int] = None
    last_error: Optional[str] = None


class DlqActionRequest(BaseModel):
    csrf_token: Optional[str] = None


class DlqActResp(BaseModel):
    requeued: Optional[int] = None
    deleted: Optional[int] = None


def _enforce_csrf(request: Request, token: Optional[str]) -> None:
    header_token = request.headers.get("X-CSRF-Token")
    candidate = header_token or token
    if not candidate:
        if not request.cookies.get("ui_csrf"):
            return
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required")
    _require_ui_csrf(request, candidate)


@router.get("/dlq", response_model=DlqStats)
def get_dlq(_: dict[str, Any] = Depends(require_viewer)) -> DlqStats:
    data = DLQ.stats()
    try:
        depth_raw = data.get("depth") if isinstance(data, dict) else None
        if depth_raw is None and isinstance(data, dict):
            depth_raw = data.get("size")
        depth_val = int(depth_raw) if depth_raw is not None else 0
        webhook_dlq_depth.set(max(0, depth_val))
    except Exception:  # pragma: no cover - defensive metrics update
        pass
    return DlqStats(**data)  # type: ignore[arg-type]


@router.post("/dlq/retry", response_model=DlqActResp)
def retry_dlq(
    payload: DlqActionRequest,
    request: Request,
    user: Dict[str, Any] = Depends(require_operator),
) -> DlqActResp:
    _enforce_csrf(request, payload.csrf_token)
    actor_email = (user or {}).get("email") if isinstance(user, dict) else None
    actor_role = (user or {}).get("role") if isinstance(user, dict) else None
    try:
        requeued = DLQ.retry_all()
    except Exception as exc:  # pragma: no cover - defensive
        try:
            admin_audit_total.labels("dlq_retry", "error").inc()
        except Exception:
            pass
        record(
            action="dlq_retry",
            actor_email=actor_email,
            actor_role=actor_role,
            outcome="error",
            meta={"error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        webhook_dlq_retry_total.inc(requeued)
    except Exception:  # pragma: no cover - metrics optional
        pass

    try:
        admin_audit_total.labels("dlq_retry", "ok").inc()
    except Exception:
        pass
    record(
        action="dlq_retry",
        actor_email=actor_email,
        actor_role=actor_role,
        outcome="ok",
        meta={"requeued": int(requeued)},
    )
    logger.info(
        "admin.webhooks.dlq.retry count=%s actor=%s",
        requeued,
        actor_email,
    )
    return DlqActResp(requeued=requeued)


@router.post("/dlq/purge", response_model=DlqActResp)
def purge_dlq(
    payload: DlqActionRequest,
    request: Request,
    user: Dict[str, Any] = Depends(require_operator),
) -> DlqActResp:
    _enforce_csrf(request, payload.csrf_token)
    actor_email = (user or {}).get("email") if isinstance(user, dict) else None
    actor_role = (user or {}).get("role") if isinstance(user, dict) else None
    try:
        deleted = DLQ.purge_all()
    except Exception as exc:  # pragma: no cover - defensive
        try:
            admin_audit_total.labels("dlq_purge", "error").inc()
        except Exception:
            pass
        record(
            action="dlq_purge",
            actor_email=actor_email,
            actor_role=actor_role,
            outcome="error",
            meta={"error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        webhook_dlq_purge_total.inc(deleted)
    except Exception:  # pragma: no cover
        pass

    try:
        admin_audit_total.labels("dlq_purge", "ok").inc()
    except Exception:
        pass
    record(
        action="dlq_purge",
        actor_email=actor_email,
        actor_role=actor_role,
        outcome="ok",
        meta={"deleted": int(deleted)},
    )
    logger.info(
        "admin.webhooks.dlq.purge count=%s actor=%s",
        deleted,
        actor_email,
    )
    return DlqActResp(deleted=deleted)
