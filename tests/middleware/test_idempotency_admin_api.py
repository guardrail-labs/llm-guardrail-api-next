import asyncio
import hashlib
import time

import httpx
import pytest
from fastapi import FastAPI
from prometheus_client import REGISTRY
from starlette.responses import JSONResponse

from app import runtime, settings
from app.idempotency.memory_store import MemoryIdemStore
from app.middleware.idempotency import IdempotencyMiddleware
from app.routes.admin_idempotency import router as admin_idempotency_router
from app.routes.admin_rbac import config_store


async def _echo(request):
    data = await request.json()
    payload = data if isinstance(data, dict) else {"body": data}
    return JSONResponse({"echo": payload, "ts": time.time()})


def _sample(name: str, labels: dict[str, str]) -> float:
    value = REGISTRY.get_sample_value(name, labels)
    return float(value) if value is not None else 0.0


@pytest.mark.asyncio
async def test_admin_idempotency_flow(monkeypatch) -> None:
    store = MemoryIdemStore(tenant="tenant-test")
    monkeypatch.setattr(runtime, "_store", store, raising=False)
    monkeypatch.setattr(config_store, "is_admin_rbac_enabled", lambda: False)
    monkeypatch.setattr(settings, "IDEMP_TOUCH_ON_REPLAY", True)

    app = FastAPI()
    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=10,
        methods=("POST",),
        touch_on_replay=True,
        tenant_provider=lambda scope: "tenant-test",
    )
    app.include_router(admin_idempotency_router)
    app.add_route("/echo", _echo, methods=["POST"])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        key = "demo-key"
        payload = {"value": 7}
        first = await client.post("/echo", json=payload, headers={"X-Idempotency-Key": key})
        assert first.headers.get("Idempotency-Replayed") == "false"

        second = await client.post("/echo", json=payload, headers={"X-Idempotency-Key": key})
        assert second.headers.get("Idempotency-Replayed") == "true"

        recent = await client.get("/admin/idempotency/recent", params={"tenant": "tenant-test"})
        assert recent.status_code == 200
        items = recent.json()
        assert items and items[0]["key"] == key
        assert items[0]["state"] == "stored"

        gauge_value = _sample("guardrail_idemp_recent_size", {"tenant": "tenant-test"})
        assert gauge_value == pytest.approx(1.0)

        inspect = await client.get(f"/admin/idempotency/{key}", params={"tenant": "tenant-test"})
        assert inspect.status_code == 200
        snapshot = inspect.json()
        assert snapshot["state"] == "stored"
        assert snapshot["replay_count"] >= 1
        assert snapshot["payload_fingerprint_prefix"]
        assert snapshot["touch_on_replay"] is True

        purge = await client.delete(f"/admin/idempotency/{key}", params={"tenant": "tenant-test"})
        assert purge.json() == {"purged": True}

        purge_again = await client.delete(
            f"/admin/idempotency/{key}", params={"tenant": "tenant-test"}
        )
        assert purge_again.json() == {"purged": False}


@pytest.mark.asyncio
async def test_admin_purge_counts_stuck_locks(monkeypatch) -> None:
    store = MemoryIdemStore(tenant="tenant-test")
    monkeypatch.setattr(runtime, "_store", store, raising=False)
    monkeypatch.setattr(config_store, "is_admin_rbac_enabled", lambda: False)

    app = FastAPI()
    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=2,
        methods=("POST",),
        touch_on_replay=False,
        tenant_provider=lambda scope: "tenant-test",
    )
    app.include_router(admin_idempotency_router)
    app.add_route("/echo", _echo, methods=["POST"])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        key = "stuck-key"
        fp = hashlib.sha256(b"stuck").hexdigest()
        await store.acquire_leader(key, 1, fp)
        await asyncio.sleep(1.1)

        before = _sample("guardrail_idemp_stuck_locks_total", {"tenant": "tenant-test"})
        resp = await client.delete(f"/admin/idempotency/{key}", params={"tenant": "tenant-test"})
        assert resp.status_code == 200
        after = _sample("guardrail_idemp_stuck_locks_total", {"tenant": "tenant-test"})
        assert after == pytest.approx(before + 1.0)
