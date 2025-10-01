"""Admin API endpoints for inspecting idempotency state."""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Mapping, Tuple

from fastapi import APIRouter, HTTPException, Query

from app.idempotency.store import IdemStore, StoredResponse
from app.runtime import idem_store

router = APIRouter(prefix="/admin/idem", tags=["admin", "idempotency"])


def _store() -> IdemStore:
    return idem_store()


def _serialize_recent(items: List[Tuple[str, float]]) -> List[List[Any]]:
    return [[key, ts] for key, ts in items]


def _serialize_stored(value: StoredResponse) -> Dict[str, Any]:
    return {
        "status": value.status,
        "headers": dict(value.headers),
        "body_b64": base64.b64encode(value.body).decode("ascii"),
        "content_type": value.content_type,
        "stored_at": value.stored_at,
        "replay_count": value.replay_count,
        "body_sha256": value.body_sha256,
    }


@router.get("/recent")
async def recent(limit: int = Query(50, ge=1, le=5000)) -> Mapping[str, Any]:
    store = _store()
    try:
        items = await store.list_recent(limit)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise HTTPException(status_code=500, detail="failed to list recent keys") from exc
    return {"items": _serialize_recent(items)}


@router.get("/meta/{key}")
async def meta(key: str) -> Mapping[str, Any]:
    store = _store()
    try:
        meta_info = await store.meta(key)
        stored = await store.get(key)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise HTTPException(status_code=500, detail="failed to load key metadata") from exc

    response: Dict[str, Any] = dict(meta_info)
    if stored:
        response["stored_response"] = _serialize_stored(stored)
    return response


@router.delete("/{key}")
async def purge(key: str) -> Mapping[str, Any]:
    store = _store()
    try:
        existed = await store.purge(key)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise HTTPException(status_code=500, detail="failed to purge key") from exc

    if not existed:
        raise HTTPException(status_code=404, detail="key not found")
    return {"ok": True}
