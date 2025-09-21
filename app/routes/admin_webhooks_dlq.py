from __future__ import annotations

import base64
import logging
import os
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.middleware.request_id import get_request_id
from app.observability.metrics import (
    webhook_dlq_purge_total,
    webhook_dlq_retry_total,
)
from app.routes.admin_ui import _require_ui_csrf
from app.security.rbac import require_operator, require_viewer
from app.services import webhooks_dlq as DLQ
from app.services.audit import emit_audit_event

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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required"
        )
    _require_ui_csrf(request, candidate)


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
        except Exception:
            pass

    env_user = os.getenv("ADMIN_UI_USER")
    if env_user:
        return env_user

    return "admin-ui"


def _audit_action(request: Request, action: str, count: Optional[int]) -> None:
    actor = _resolve_actor(request)
    request_id = get_request_id() or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    event: Dict[str, Any] = {
        "action": f"admin.webhooks.dlq.{action}",
        "actor": actor,
        "request_id": request_id,
    }
    if count is not None:
        event["count"] = count

    try:
        emit_audit_event(event)
    except Exception:
        logger.exception("failed to emit audit event", extra={"action": action})
    logger.info(
        "admin.webhooks.dlq.%s count=%s actor=%s request_id=%s",
        action,
        count,
        actor,
        request_id,
    )


@router.get("/dlq", response_model=DlqStats)
def get_dlq(_: dict[str, Any] = Depends(require_viewer)) -> DlqStats:
    data = DLQ.stats()
    return DlqStats(**data)  # type: ignore[arg-type]


@router.post("/dlq/retry", response_model=DlqActResp)
def retry_dlq(
    payload: DlqActionRequest,
    request: Request,
    _: dict[str, Any] = Depends(require_operator),
) -> DlqActResp:
    _enforce_csrf(request, payload.csrf_token)
    try:
        requeued = DLQ.retry_all()
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail="DLQ retry failed") from exc

    try:
        webhook_dlq_retry_total.inc(requeued)
    except Exception:  # pragma: no cover - metrics optional
        pass

    _audit_action(request, "retry", requeued)
    return DlqActResp(requeued=requeued)


@router.post("/dlq/purge", response_model=DlqActResp)
def purge_dlq(
    payload: DlqActionRequest,
    request: Request,
    _: dict[str, Any] = Depends(require_operator),
) -> DlqActResp:
    _enforce_csrf(request, payload.csrf_token)
    try:
        deleted = DLQ.purge_all()
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail="DLQ purge failed") from exc

    try:
        webhook_dlq_purge_total.inc(deleted)
    except Exception:  # pragma: no cover
        pass

    _audit_action(request, "purge", deleted)
    return DlqActResp(deleted=deleted)
