from __future__ import annotations

import time
from typing import Any, List, Mapping

from fastapi import APIRouter, Depends, HTTPException, Query

from app import settings
from app.idempotency.log_utils import log_idempotency_event
from app.idempotency.memory_store import MemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import IdemStore
from app.metrics import IDEMP_PURGES, IDEMP_RECENT_SIZE, IDEMP_STUCK_LOCKS
from app.routes.admin_rbac import require_admin
from app.runtime import idem_store as runtime_idem_store
from app.runtime import redis_client

router = APIRouter(prefix="/admin/idempotency", tags=["Admin / Idempotency"])


def _normalize_tenant(raw: str | None) -> str:
    tenant = (raw or "").strip()
    if not tenant:
        raise HTTPException(status_code=400, detail="tenant is required")
    return tenant


def _resolve_store(tenant: str) -> IdemStore:
    base = runtime_idem_store()
    base_tenant = getattr(base, "tenant", "default")
    if base_tenant == tenant:
        return base
    if isinstance(base, MemoryIdemStore):
        raise HTTPException(status_code=404, detail="unknown tenant")
    if isinstance(base, RedisIdemStore):
        return RedisIdemStore(
            redis_client(),
            ns=base.ns,
            tenant=tenant,
            recent_limit=base.recent_limit,
            release_state_ttl=base.release_state_ttl,
        )
    raise HTTPException(status_code=404, detail="unknown tenant")


async def _inspect(store: IdemStore, key: str) -> Mapping[str, Any]:
    try:
        return await store.inspect(key)
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail="inspect not supported") from exc


@router.get("/recent")
async def list_recent(
    tenant: str = Query(..., description="Tenant identifier"),
    limit: int = Query(50, ge=1, le=500, description="Maximum entries to return"),
    _admin: None = Depends(require_admin),
) -> List[Mapping[str, Any]]:
    tenant_id = _normalize_tenant(tenant)
    if limit > 500:
        raise HTTPException(status_code=400, detail="limit must be <= 500")
    store = _resolve_store(tenant_id)
    try:
        raw_items = await store.list_recent(limit=limit)
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail="list_recent not supported") from exc

    results: List[Mapping[str, Any]] = []
    seen: set[str] = set()
    for key, last_seen in raw_items:
        key_str = str(key)
        if key_str in seen:
            continue
        seen.add(key_str)
        snapshot = await _inspect(store, key_str)
        first_seen = float(snapshot.get("first_seen_at") or 0.0)
        results.append(
            {
                "key": key_str,
                "first_seen_at": first_seen,
                "last_seen_at": float(last_seen),
                "state": str(snapshot.get("state") or "missing"),
                "replay_count": int(snapshot.get("replay_count") or 0),
            }
        )

    IDEMP_RECENT_SIZE.labels(tenant=tenant_id).set(len(results))
    return results


@router.get("/{key}")
async def inspect_key(
    key: str,
    tenant: str = Query(..., description="Tenant identifier"),
    _admin: None = Depends(require_admin),
) -> Mapping[str, Any]:
    tenant_id = _normalize_tenant(tenant)
    store = _resolve_store(tenant_id)
    snapshot = await _inspect(store, key)
    state = str(snapshot.get("state") or "missing")
    return {
        "state": state,
        "expires_at": float(snapshot.get("expires_at") or 0.0),
        "replay_count": int(snapshot.get("replay_count") or 0),
        "stored_at": float(snapshot.get("stored_at") or 0.0),
        "size_bytes": int(snapshot.get("size_bytes") or 0),
        "content_type": snapshot.get("content_type"),
        "payload_fingerprint_prefix": snapshot.get("payload_fingerprint_prefix"),
        "first_seen_at": float(snapshot.get("first_seen_at") or 0.0),
        "touch_on_replay": bool(settings.IDEMP_TOUCH_ON_REPLAY),
    }


@router.delete("/{key}")
async def purge_key(
    key: str,
    tenant: str = Query(..., description="Tenant identifier"),
    _admin: None = Depends(require_admin),
) -> Mapping[str, Any]:
    tenant_id = _normalize_tenant(tenant)
    store = _resolve_store(tenant_id)
    try:
        snapshot = await store.inspect(key)
    except NotImplementedError:
        snapshot = {}
    existed = await store.purge(key)
    IDEMP_PURGES.labels(tenant=tenant_id).inc()

    state = str(snapshot.get("state") or "missing") if isinstance(snapshot, Mapping) else "missing"
    expires_at = float(snapshot.get("expires_at") or 0.0) if isinstance(snapshot, Mapping) else 0.0
    replay_count = int(snapshot.get("replay_count") or 0) if isinstance(snapshot, Mapping) else 0
    fp_prefix = None
    if isinstance(snapshot, Mapping):
        fp_prefix = snapshot.get("payload_fingerprint_prefix")

    stuck = bool(state == "in_progress" and expires_at and expires_at < time.time())
    if stuck:
        IDEMP_STUCK_LOCKS.labels(tenant=tenant_id).inc()

    log_idempotency_event(
        "purge",
        key=key,
        tenant=tenant_id,
        role="admin",
        state=state,
        replay_count=replay_count,
        fp_prefix=fp_prefix,
        stuck=stuck,
    )

    return {"purged": bool(existed)}
