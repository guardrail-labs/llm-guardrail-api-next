from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.routes.admin_rbac import require_admin
from app.routes.admin_ui import require_auth
from app.routes.admin_webhooks import _require_csrf_dep
from app.runtime import get_dlq_service
from app.services.dlq import DLQMessage, DLQService

router = APIRouter(prefix="/admin/webhooks/dlq", tags=["admin-webhook-dlq"])


def _ensure_scope(tenant: str | None, topic: str | None) -> tuple[str, str]:
    if not tenant:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant required")
    if not topic:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="topic required")
    return tenant, topic


def _serialize_message(message: DLQMessage) -> dict[str, Any]:
    return {
        "id": message.id,
        "tenant": message.tenant,
        "topic": message.topic,
        "payload": message.payload,
        "tries": message.tries,
        "created_ts": message.created_ts,
        "first_failure_ts": message.first_failure_ts,
        "last_attempt_ts": message.last_attempt_ts,
        "next_attempt_ts": message.next_attempt_ts,
        "last_error": message.last_error,
    }


@router.get("/pending")
async def list_pending_dlq(
    tenant: str | None = Query(None),
    topic: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    dlq: DLQService = Depends(get_dlq_service),
) -> dict[str, Any]:
    scope_tenant, scope_topic = _ensure_scope(tenant, topic)
    messages = await dlq.list_pending(scope_tenant, scope_topic, limit=limit)
    return {"messages": [_serialize_message(msg) for msg in messages]}


@router.get("/quarantine")
async def list_quarantine_dlq(
    tenant: str | None = Query(None),
    topic: str | None = Query(None),
    limit: int = Query(200, ge=1, le=500),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    dlq: DLQService = Depends(get_dlq_service),
) -> dict[str, Any]:
    scope_tenant, scope_topic = _ensure_scope(tenant, topic)
    ids = await dlq.list_quarantine(scope_tenant, scope_topic, limit=limit)
    return {"ids": ids}


@router.post("/{msg_id}/replay")
async def replay_message(
    msg_id: str,
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
    dlq: DLQService = Depends(get_dlq_service),
) -> dict[str, Any]:
    message = await dlq.replay_now(msg_id)
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="message not found")
    return {"id": message.id, "next_attempt_ts": message.next_attempt_ts}


@router.delete("/{msg_id}")
async def delete_message(
    msg_id: str,
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
    dlq: DLQService = Depends(get_dlq_service),
) -> dict[str, str]:
    deleted = await dlq.ack(msg_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="message not found")
    return {"status": "deleted"}
