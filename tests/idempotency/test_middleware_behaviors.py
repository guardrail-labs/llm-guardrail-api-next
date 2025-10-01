import asyncio
import json
from typing import Any, Dict

import pytest
from fastapi import FastAPI, Request, Response
from httpx import ASGITransport, AsyncClient

from app.middleware.idempotency import IdempotencyMiddleware
from app.idempotency.memory_store import MemoryIdemStore


def _build_basic_app(store: MemoryIdemStore) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: Dict[str, Any], request: Request, response: Response) -> Dict[str, Any]:
        header_val = request.headers.get("x-custom-test")
        if header_val:
            response.headers["X-Custom-Test"] = header_val
        return {"ok": True, "payload": payload}

    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=60,
        methods=("POST",),
        max_body=1_000_000,
        cache_streaming=False,
        tenant_provider=lambda scope: "test",
    )
    return app


@pytest.mark.asyncio
async def test_first_run_false_then_replay_true(app_with_idem: FastAPI) -> None:
    key = "replay-demo"
    body = {"a": 1}
    transport = ASGITransport(app=app_with_idem, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as idem_client:
        r1 = await idem_client.post(
            "/echo", json=body, headers={"X-Idempotency-Key": key}
        )
        assert r1.status_code == 200
        assert r1.headers.get("idempotency-replayed") == "false"

        r2 = await idem_client.post(
            "/echo", json=body, headers={"X-Idempotency-Key": key}
        )
        assert r2.status_code == 200
        assert r2.headers.get("idempotency-replayed") == "true"
        assert r2.json()["payload"] == body


@pytest.mark.asyncio
async def test_same_key_different_body_overwrites_cache(app_with_idem: FastAPI):
    key = "swap-body"
    b1 = {"x": 1}
    b2 = {"x": 2}
    transport = ASGITransport(app=app_with_idem, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as idem_client:
        r1 = await idem_client.post("/echo", json=b1, headers={"X-Idempotency-Key": key})
        assert r1.status_code == 200
        assert r1.headers.get("idempotency-replayed") == "false"

        r2 = await idem_client.post(
            "/echo", json=b2, headers={"X-Idempotency-Key": key}
        )
        assert r2.status_code == 200
        assert r2.headers.get("idempotency-replayed") == "false"
        assert r2.json()["payload"] == b2

        r3 = await idem_client.post(
            "/echo", json=b2, headers={"X-Idempotency-Key": key}
        )
        assert r3.status_code == 200
        assert r3.headers.get("idempotency-replayed") == "true"
        assert r3.json()["payload"] == b2


@pytest.mark.asyncio
async def test_replay_preserves_custom_and_security_headers(
    app_with_idem: FastAPI,
) -> None:
    key = "hdrs"
    transport = ASGITransport(app=app_with_idem, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as idem_client:
        r1 = await idem_client.post(
            "/echo",
            json={"a": "b"},
            headers={"X-Idempotency-Key": key, "X-Custom-Test": "1"},
        )
        assert r1.status_code == 200
        assert r1.headers.get("idempotency-replayed") == "false"

        r2 = await idem_client.post(
            "/echo",
            json={"a": "b"},
            headers={"X-Idempotency-Key": key, "X-Custom-Test": "1"},
        )
        assert r2.status_code == 200
        assert r2.headers.get("idempotency-replayed") == "true"
        assert r2.headers.get("x-custom-test") == "1"


@pytest.mark.asyncio
async def test_follower_proceeds_when_streaming_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryIdemStore()
    app = _build_basic_app(store)

    async def fake_run(self, scope, body):
        await asyncio.sleep(0.05)
        return 200, {"content-type": "text/plain"}, b"part1-part2", True

    monkeypatch.setattr(IdempotencyMiddleware, "_run_downstream", fake_run)

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r1 = await ac.post("/echo", headers={"X-Idempotency-Key": "S"})
        assert r1.status_code == 200
        assert r1.headers.get("idempotency-replayed") == "false"
        assert r1.text == "part1-part2"

        r2 = await ac.post("/echo", headers={"X-Idempotency-Key": "S"})
        assert r2.status_code == 200
        assert r2.headers.get("idempotency-replayed") == "false"
        assert r2.text == "part1-part2"


@pytest.mark.asyncio
async def test_lock_released_on_downstream_exception() -> None:
    store = MemoryIdemStore()
    app = FastAPI()

    @app.post("/boom")
    async def boom():
        raise RuntimeError("kapow")

    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=60,
        methods=("POST",),
        max_body=1_000_000,
        cache_streaming=False,
        tenant_provider=lambda scope: "test",
    )

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        async def call():
            return await ac.post("/boom", headers={"X-Idempotency-Key": "E"})

        r1, r2 = await asyncio.gather(call(), call())
        assert r1.status_code == r2.status_code == 500

        meta = await store.meta("E")
        assert meta.get("lock") is False
        assert meta.get("state") is None or meta.get("state") != "in_progress"


@pytest.mark.asyncio
async def test_non_cached_large_body_releases_lock() -> None:
    store = MemoryIdemStore()
    app = FastAPI()

    @app.post("/big")
    async def big(payload: dict) -> dict:
        return {"n": len(json.dumps(payload))}

    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=60,
        methods=("POST",),
        max_body=16,
        cache_streaming=False,
        tenant_provider=lambda scope: "test",
    )

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        big_body = {"x": "y" * 64}

        async def call():
            return await ac.post(
                "/big",
                json=big_body,
                headers={"X-Idempotency-Key": "B"},
            )

        r1, r2 = await asyncio.gather(call(), call())
        assert r1.status_code == r2.status_code == 200
        vals = {r.headers.get("idempotency-replayed") for r in (r1, r2)}
        assert vals == {"false"}
