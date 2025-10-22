from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app import settings
from app.observability.admin_audit import record
from app.observability.metrics import (
    admin_audit_total,
    retention_deleted_total,
    retention_preview_total,
)
from app.routes.admin_mitigation import require_csrf
from app.routes.admin_rbac import require_admin
from app.routes.admin_ui import require_auth
from app.routes.admin_webhooks import _require_csrf_dep
from app.runtime import get_purge_coordinator, get_retention_store
from app.security.rbac import RBACError, ensure_scope, require_operator, require_viewer
from app.services import retention as retention_service
from app.services.purge_coordinator import PurgeCoordinator
from app.services.retention import Resource, RetentionPolicy, RetentionStore

router = APIRouter(prefix="/admin", tags=["admin-retention"])

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


@router.post("/api/retention/preview", response_model=PreviewResp)
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


class PolicyPayload(BaseModel):
    tenant: str
    resource: str
    ttl_seconds: int = Field(..., ge=0)
    enabled: bool = True


class PlanRequest(BaseModel):
    tenant: str
    resource: str
    limit: int = Field(
        default=settings.RETENTION_MAX_IDS_PER_RUN,
        ge=1,
        le=settings.RETENTION_MAX_IDS_PER_RUN,
    )


class PlanResponse(BaseModel):
    ids: List[str]
    count: int


class PurgeRequest(BaseModel):
    tenant: str
    resource: str
    ids: Optional[List[str]] = None
    limit: Optional[int] = Field(
        default=None,
        ge=1,
        le=settings.RETENTION_MAX_IDS_PER_RUN,
    )
    dry_run: bool = False
    actor: Optional[str] = None
    mode: Optional[str] = None


class PurgeResponse(BaseModel):
    receipt: Dict[str, Any]
    signature: Dict[str, str]


def _coerce_resource(value: str) -> Resource:
    try:
        return Resource(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="unknown resource") from exc


def _policy_to_dict(policy: RetentionPolicy) -> Dict[str, Any]:
    return {
        "tenant": policy.tenant,
        "resource": policy.resource.value,
        "ttl_seconds": int(policy.ttl_seconds),
        "enabled": bool(policy.enabled),
    }


def _ensure_csrf_token(token: Optional[str]) -> None:
    if token and token.strip():
        return
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF token required")


@router.post("/api/retention/execute", response_model=ExecuteResp)
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


@router.get("/retention/policies")
async def list_policies_admin(
    tenant: Optional[str] = None,
    store: RetentionStore = Depends(get_retention_store),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> Dict[str, Any]:
    policies = await store.list_policies(tenant=tenant)
    return {"policies": [_policy_to_dict(policy) for policy in policies]}


@router.put("/retention/policies", response_model=Dict[str, Any])
async def upsert_policy_admin(
    payload: PolicyPayload,
    store: RetentionStore = Depends(get_retention_store),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> Dict[str, Any]:
    resource = _coerce_resource(payload.resource)
    policy = RetentionPolicy(
        tenant=payload.tenant,
        resource=resource,
        ttl_seconds=payload.ttl_seconds,
        enabled=payload.enabled,
    )
    await store.set_policy(policy)
    return {"policy": _policy_to_dict(policy)}


@router.post("/retention/plan", response_model=PlanResponse)
async def plan_purge_admin(
    payload: PlanRequest,
    coordinator: PurgeCoordinator = Depends(get_purge_coordinator),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> PlanResponse:
    resource = _coerce_resource(payload.resource)
    limit = payload.limit or settings.RETENTION_MAX_IDS_PER_RUN
    now = time.time()
    ids = await coordinator.plan(payload.tenant, resource.value, now, limit)
    return PlanResponse(ids=ids, count=len(ids))


@router.post("/retention/purge", response_model=PurgeResponse)
async def purge_admin(
    payload: PurgeRequest,
    coordinator: PurgeCoordinator = Depends(get_purge_coordinator),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> PurgeResponse:
    resource = _coerce_resource(payload.resource)
    limit = payload.limit or settings.RETENTION_MAX_IDS_PER_RUN
    ids = list(payload.ids or [])
    if not ids:
        ids = await coordinator.plan(
            payload.tenant, resource.value, time.time(), limit
        )
    else:
        ids = ids[:limit]
    receipt = await coordinator.execute(
        payload.tenant,
        resource.value,
        ids,
        dry_run=payload.dry_run,
        actor=payload.actor or "admin-api",
        mode=(payload.mode or "manual"),
    )
    stored = await coordinator.get_receipt(receipt.id)
    signature = stored[1] if stored else {}
    return PurgeResponse(
        receipt=receipt.to_payload(),
        signature=signature,
    )


@router.get("/retention/receipts")
async def list_receipts_admin(
    tenant: str,
    limit: int = 50,
    coordinator: PurgeCoordinator = Depends(get_purge_coordinator),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> Dict[str, Any]:
    limit = max(1, min(limit, settings.RETENTION_MAX_IDS_PER_RUN))
    receipts = await coordinator.latest_receipts(tenant, limit)
    return {"receipts": [receipt.to_payload() for receipt in receipts]}


@router.get("/retention/receipts/{receipt_id}")
async def get_receipt_admin(
    receipt_id: str,
    coordinator: PurgeCoordinator = Depends(get_purge_coordinator),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> Dict[str, Any]:
    stored = await coordinator.get_receipt(receipt_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    receipt, signature = stored
    return {"receipt": receipt.to_payload(), "signature": signature}


@router.post("/retention/verify/{receipt_id}")
async def verify_receipt_admin(
    receipt_id: str,
    coordinator: PurgeCoordinator = Depends(get_purge_coordinator),
    _: None = Depends(require_auth),
    __: None = Depends(require_admin),
    ___: None = Depends(_require_csrf_dep),
) -> Dict[str, bool]:
    valid = await coordinator.verify_receipt(receipt_id)
    return {"valid": valid}
