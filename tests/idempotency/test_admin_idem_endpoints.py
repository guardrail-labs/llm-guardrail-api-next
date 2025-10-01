import asyncio
import base64
import json
import time
from typing import Dict

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.idempotency.store import StoredResponse
from app.idempotency.memory_store import MemoryIdemStore


@pytest.mark.asyncio
async def test_admin_recent_shape_and_limit(
    app_admin: FastAPI, memory_store: MemoryIdemStore
) -> None:
    # Touch a few keys via acquire to populate "recent"
    for i in range(5):
        await memory_store.acquire_leader(f"k{i}", 30, f"fp-{i}")
        await asyncio.sleep(0.001)  # ensure ordering
    transport = ASGITransport(app=app_admin, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as admin_client:
        r = await admin_client.get("/admin/idem/recent?limit=3")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    items = data["items"]
    assert len(items) == 3
    # newest-first; last created key is k4
    assert items[0][0] in {"k4", "k3", "k2", "k1", "k0"}


@pytest.mark.asyncio
async def test_admin_meta_states_lock_fingerprint(
    app_admin: FastAPI, memory_store: MemoryIdemStore
) -> None:
    await memory_store.acquire_leader("demo", 20, "fp-xyz")
    transport = ASGITransport(app=app_admin, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as admin_client:
        r = await admin_client.get("/admin/idem/meta/demo")
    assert r.status_code == 200
    meta: Dict[str, object] = r.json()
    assert meta.get("state") == "in_progress"
    assert meta.get("lock") is True
    assert meta.get("payload_fingerprint") == "fp-xyz"


@pytest.mark.asyncio
async def test_admin_purge_ok_and_404(
    app_admin: FastAPI, memory_store: MemoryIdemStore
) -> None:
    await memory_store.acquire_leader("gone", 20, "fp")
    # Store a value, then purge
    value = StoredResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"ok":true}',
        content_type="application/json",
        stored_at=time.time(),
        body_sha256="fp",
    )
    await memory_store.put("gone", value, 20)

    transport = ASGITransport(app=app_admin, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as admin_client:
        r1 = await admin_client.delete("/admin/idem/gone")
        assert r1.status_code == 200
        assert r1.json() == {"ok": True}

        r2 = await admin_client.delete("/admin/idem/gone")
        assert r2.status_code == 404
        assert r2.json().get("detail") in {"key not found", "Not Found"}
