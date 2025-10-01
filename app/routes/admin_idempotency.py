from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app import settings
from app.idempotency.memory_store import MemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import IdemStore
from app.idempotency.utils import mask_idempotency_key
from app.metrics import IDEMP_PURGES, IDEMP_RECENT_SIZE, IDEMP_STUCK_LOCKS
from app.routes.admin_rbac import require_admin
from app.runtime import idem_store, redis_client

router = APIRouter(prefix="/admin/idempotency", tags=["Admin", "Idempotency"])

_log = logging.getLogger("guardrail.idempotency")


class RecentEntry(BaseModel):
    key: str = Field(..., description="Idempotency key")
    first_seen_at: Optional[float] = Field(
        None, description="Epoch seconds when the key first appeared"
    )
    last_seen_at: Optional[float] = Field(
        None, description="Epoch seconds when the key was last touched"
    )
    state: str = Field(..., description="Current state in the store")
    replay_count: Optional[int] = Field(
        None, description="Replay count recorded for the stored response"
    )


class RecentResponse(BaseModel):
    tenant: str
    limit: int
    entries: List[RecentEntry]


class InspectResponse(BaseModel):
    key: str
    tenant: str
    state: str
    expires_at: float
    replay_count: Optional[int] = None
    stored_at: float = 0.0
    size_bytes: int = 0
    content_type: Optional[str] = None
    payload_fingerprint_prefix: Optional[str] = None
    touch_on_replay: bool


class PurgeResponse(BaseModel):
    key: str
    tenant: str
    purged: bool


def _fp_prefix(value: Any) -> Optional[str]:
    if not value:
        return None
    return str(value)[:8]


def _resolve_store(tenant: str) -> IdemStore:
    base = idem_store()
    base_tenant = getattr(base, "tenant", "default")
    if tenant == base_tenant:
        return base
    if isinstance(base, RedisIdemStore):
        return RedisIdemStore(
            redis_client(),
            ns=base.ns,
            tenant=tenant,
            recent_limit=base.recent_limit,
            release_state_ttl=base.release_state_ttl,
        )
    if isinstance(base, MemoryIdemStore):
        raise HTTPException(status_code=404, detail="unknown tenant")
    raise HTTPException(status_code=404, detail="unknown tenant")


def _recent_aggregate(items: Iterable[tuple[str, float]]) -> Dict[str, Dict[str, float]]:
    aggregated: Dict[str, Dict[str, float]] = {}
    for key, ts in items:
        entry = aggregated.setdefault(key, {"first_seen_at": ts, "last_seen_at": ts})
        entry["first_seen_at"] = min(entry["first_seen_at"], ts)
        entry["last_seen_at"] = max(entry["last_seen_at"], ts)
    return aggregated


def _log_admin_event(
    event: str,
    *,
    key: str,
    tenant: str,
    state: str,
    replay_count: Optional[int],
    fp_prefix: Optional[str],
) -> None:
    try:
        _log.info(
            event,
            extra={
                "idempotency_key": mask_idempotency_key(key),
                "tenant": tenant,
                "role": "admin",
                "state": state,
                "replay_count": replay_count,
                "fp_prefix": fp_prefix,
                "wait_ms": 0.0,
            },
        )
    except Exception:
        pass


@router.get(
    "/recent",
    response_model=RecentResponse,
    summary="List recent idempotency keys",
    description="Inspect the most recently seen idempotency keys for a tenant.",
)
async def list_recent(
    *,
    limit: int = Query(50, ge=1, description="Maximum number of entries to return (<=500)"),
    tenant: str = Query("default", min_length=1, description="Tenant namespace"),
    _admin: None = Depends(require_admin),
) -> RecentResponse:
    if limit > 500:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit too large")

    store = _resolve_store(tenant)
    recent_raw = await store.list_recent(limit=limit)
    aggregated = _recent_aggregate(recent_raw)

    entries: List[RecentEntry] = []
    for key, windows in aggregated.items():
        snapshot = await store.inspect(key)
        state = str(snapshot.get("state") or "missing")
        replay_count = snapshot.get("replay_count")
        if isinstance(replay_count, (int, float)):
            replay_count_int: Optional[int] = int(replay_count)
        else:
            replay_count_int = None
        first_seen = snapshot.get("first_seen_at", windows["first_seen_at"])
        last_seen = snapshot.get("last_seen_at", windows["last_seen_at"])
        entries.append(
            RecentEntry(
                key=key,
                first_seen_at=float(first_seen) if first_seen is not None else None,
                last_seen_at=float(last_seen) if last_seen is not None else None,
                state=state,
                replay_count=replay_count_int,
            )
        )

    entries.sort(key=lambda item: item.last_seen_at or 0.0, reverse=True)
    IDEMP_RECENT_SIZE.labels(tenant=tenant).set(len(entries))
    return RecentResponse(tenant=tenant, limit=limit, entries=entries)


@router.get(
    "/{key}",
    response_model=InspectResponse,
    summary="Inspect a specific idempotency key",
)
async def inspect_key(
    key: str,
    *,
    tenant: str = Query("default", min_length=1, description="Tenant namespace"),
    _admin: None = Depends(require_admin),
) -> InspectResponse:
    store = _resolve_store(tenant)
    snapshot = await store.inspect(key)
    state = str(snapshot.get("state") or "missing")
    expires_at = float(snapshot.get("expires_at") or 0.0)
    stored_at = float(snapshot.get("stored_at") or 0.0)
    size_bytes = int(snapshot.get("size_bytes") or 0)
    replay_count = snapshot.get("replay_count")
    if isinstance(replay_count, (int, float)):
        replay_int: Optional[int] = int(replay_count)
    else:
        replay_int = None
    content_type = snapshot.get("content_type")
    payload_prefix = _fp_prefix(snapshot.get("payload_fingerprint_prefix"))

    return InspectResponse(
        key=key,
        tenant=tenant,
        state=state,
        expires_at=expires_at,
        replay_count=replay_int,
        stored_at=stored_at,
        size_bytes=size_bytes,
        content_type=content_type if isinstance(content_type, str) else None,
        payload_fingerprint_prefix=payload_prefix,
        touch_on_replay=bool(settings.IDEMP_TOUCH_ON_REPLAY),
    )


@router.delete(
    "/{key}",
    response_model=PurgeResponse,
    summary="Purge an idempotency key",
)
async def purge_key(
    key: str,
    *,
    tenant: str = Query("default", min_length=1, description="Tenant namespace"),
    _admin: None = Depends(require_admin),
) -> PurgeResponse:
    store = _resolve_store(tenant)
    snapshot = await store.inspect(key)
    state = str(snapshot.get("state") or "missing")
    expires_at = float(snapshot.get("expires_at") or 0.0)
    replay_count = snapshot.get("replay_count")
    if isinstance(replay_count, (int, float)):
        replay_int: Optional[int] = int(replay_count)
    else:
        replay_int = None
    fp_prefix = _fp_prefix(snapshot.get("payload_fingerprint_prefix"))

    purged = await store.purge(key)
    if purged:
        IDEMP_PURGES.labels(tenant=tenant).inc()
    stuck_lock = purged and state == "in_progress" and expires_at and expires_at < time.time()
    if stuck_lock:
        IDEMP_STUCK_LOCKS.labels(tenant=tenant).inc()

    final_state = "purged" if purged else state
    _log_admin_event(
        "idemp_admin_purge",
        key=key,
        tenant=tenant,
        state=final_state,
        replay_count=replay_int,
        fp_prefix=fp_prefix,
    )

    return PurgeResponse(key=key, tenant=tenant, purged=bool(purged))

