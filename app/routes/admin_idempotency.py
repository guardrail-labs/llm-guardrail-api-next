"""Debug helpers for inspecting idempotency cache state."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.idempotency.store import IdemStore
from app.observability.metrics_idempotency import IDEMP_EVICTIONS
from app.runtime import idem_store

router = APIRouter(prefix="/admin/idempotency", tags=["admin-idempotency"])


def get_store() -> IdemStore:
    return idem_store()


@router.get("/recent")
async def recent(
    limit: int = Query(50, ge=1, le=500),
    store: IdemStore = Depends(get_store),
) -> list[Dict[str, Any]]:
    items = await store.list_recent(limit)
    return [{"key": key, "ts": ts} for key, ts in items]


@router.get("/{key}")
async def meta(key: str, store: IdemStore = Depends(get_store)) -> Dict[str, Any]:
    return dict(await store.meta(key))


@router.delete("/{key}")
async def purge(key: str, store: IdemStore = Depends(get_store)) -> Dict[str, bool]:
    removed = await store.purge(key)
    if not removed:
        raise HTTPException(status_code=404, detail="not_found")
    IDEMP_EVICTIONS.labels(tenant="default", reason="purge").inc()
    return {"deleted": True}
