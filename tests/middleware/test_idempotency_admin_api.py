import asyncio

import prometheus_client
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

import app.runtime as runtime
from app import settings
from app.idempotency.memory_store import MemoryIdemStore
from app.middleware.idempotency import IdempotencyMiddleware
from app.routes import admin_idempotency


def _build_app(store: MemoryIdemStore, *, touch_on_replay: bool) -> FastAPI:
    runtime._store = store
    app = FastAPI()
    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=30,
        methods=("POST",),
        max_body=1024,
        cache_streaming=False,
        tenant_provider=lambda scope: store.tenant,
        touch_on_replay=touch_on_replay,
    )

    @app.post("/echo")
    async def echo(payload: dict) -> JSONResponse:  # pragma: no cover - trivial
        return JSONResponse(payload)

    app.include_router(admin_idempotency.router)
    return app


def test_admin_routes_cover_recent_inspect_and_purge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "IDEMP_TOUCH_ON_REPLAY", True, raising=False)
    store = MemoryIdemStore(tenant="tenant-test", recent_limit=20)
    app = _build_app(store, touch_on_replay=True)

    with TestClient(app) as client:
        headers = {"X-Idempotency-Key": "demo-key"}
        body = {"hello": "world"}

        r1 = client.post("/echo", json=body, headers=headers)
        assert r1.status_code == 200
        r2 = client.post("/echo", json=body, headers=headers)
        assert r2.status_code == 200
        assert r2.headers.get("Idempotency-Replayed") == "true"

        recent = client.get("/admin/idempotency/recent", params={"tenant": "tenant-test"})
        assert recent.status_code == 200
        recent_payload = recent.json()
        assert recent_payload["entries"][0]["key"] == "demo-key"
        assert recent_payload["entries"][0]["state"] == "stored"
        assert recent_payload["entries"][0]["replay_count"] == 1

        detail = client.get("/admin/idempotency/demo-key", params={"tenant": "tenant-test"})
        assert detail.status_code == 200
        detail_payload = detail.json()
        assert detail_payload["touch_on_replay"] is True
        assert detail_payload["size_bytes"] > 0
        assert detail_payload["payload_fingerprint_prefix"]
        assert len(detail_payload["payload_fingerprint_prefix"]) == 8

        delete = client.delete("/admin/idempotency/demo-key", params={"tenant": "tenant-test"})
        assert delete.status_code == 200
        assert delete.json()["purged"] is True

        missing = client.get("/admin/idempotency/demo-key", params={"tenant": "tenant-test"})
        assert missing.status_code == 200
        assert missing.json()["state"] == "missing"

        # limit guard
        too_large = client.get(
            "/admin/idempotency/recent", params={"tenant": "tenant-test", "limit": 600}
        )
        assert too_large.status_code == 400

        # create a stuck lock by expiring the lock manually
        asyncio.run(store.acquire_leader("stuck", 1, "ffffffff"))
        if "stuck" in store._locks:
            store._locks["stuck"]["expiry"] = store._now() - 10
        if "stuck" in store._states:
            store._states["stuck"] = ("in_progress", store._now() - 10)

        stuck_delete = client.delete(
            "/admin/idempotency/stuck", params={"tenant": "tenant-test"}
        )
        assert stuck_delete.status_code == 200
        assert stuck_delete.json()["purged"] is True

    metrics_text = prometheus_client.generate_latest(prometheus_client.REGISTRY).decode("utf-8")
    assert 'guardrail_idemp_purges_total{tenant="tenant-test"} 2.0' in metrics_text
    assert 'guardrail_idemp_stuck_locks_total{tenant="tenant-test"} 1.0' in metrics_text
    assert 'guardrail_idemp_recent_size{tenant="tenant-test"}' in metrics_text
