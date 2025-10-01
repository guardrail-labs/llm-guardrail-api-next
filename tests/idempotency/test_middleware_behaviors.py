import asyncio
import json
from typing import Any, Dict

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

# Import the fixture module to register fixtures without shadowing names.
from . import fixtures_idempotency as _fixtures  # noqa: F401

from app.middleware.idempotency import IdempotencyMiddleware
from app.idempotency.memory_store import MemoryIdemStore


async def _asgi_streaming_app(scope, receive, send):
    """
    A tiny ASGI app that produces streaming body (two chunks).
    The idempotency middleware will detect streaming via more_body=True.
    """
    assert scope["type"] == "http"
    if scope["path"] != "/stream":
        # 404 for anything else
        await send(
            {
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"nope"})
        return

    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"x-custom-test", b"1")],
        }
    )
    # first chunk
    await send({"type": "http.response.body", "body": b"part1-", "more_body": True})
    # simulate some processing delay to keep leader "busy"
    await asyncio.sleep(0.05)
    # final chunk
    await send({"type": "http.response.body", "body": b"part2", "more_body": False})


def _wrap_streaming_with_middleware(store: MemoryIdemStore) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "payload": payload}

    # Mount the raw ASGI streaming app under /stream
    app.router.add_api_route("/stream", _asgi_streaming_app, methods=["POST"])

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
async def test_first_run_false_then_replay_true(idem_client: AsyncClient) -> None:
    key = "replay-demo"
    body = {"a": 1}
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
async def test_same_key_different_body_overwrites_cache(idem_client: AsyncClient):
    key = "swap-body"
    b1 = {"x": 1}
    b2 = {"x": 2}

    r1 = await idem_client.post("/echo", json=b1, headers={"X-Idempotency-Key": key})
    assert r1.status_code == 200
    assert r1.headers.get("idempotency-replayed") == "false"

    # Different body, same key -> treated as fresh run (overwrite), not replay
    r2 = await idem_client.post("/echo", json=b2, headers={"X-Idempotency-Key": key})
    assert r2.status_code == 200
    assert r2.headers.get("idempotency-replayed") == "false"
    assert r2.json()["payload"] == b2

    # Now replay should reflect latest body
    r3 = await idem_client.post("/echo", json=b2, headers={"X-Idempotency-Key": key})
    assert r3.status_code == 200
    assert r3.headers.get("idempotency-replayed") == "true"
    assert r3.json()["payload"] == b2


@pytest.mark.asyncio
async def test_follower_proceeds_when_streaming_not_cached() -> None:
    """
    Two concurrent requests to /stream with same idempotency key.
    Leader streams and does NOT cache (cache_streaming=False).
    Follower must proceed after lock clears; not a replay (header=false).
    """
    store = MemoryIdemStore()
    app = _wrap_streaming_with_middleware(store)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        async def call():
            return await ac.post("/stream", headers={"X-Idempotency-Key": "S"})

        # Fire both concurrently; the follower should complete quickly after the leader.
        r1, r2 = await asyncio.gather(call(), call())
        vals = {r.headers.get("idempotency-replayed") for r in (r1, r2)}
        # Because streaming path does not cache, both should be "false"
        assert vals == {"false"}
        assert r1.status_code == r2.status_code == 200
        assert r1.text == r2.text == "part1-part2"


@pytest.mark.asyncio
async def test_lock_released_on_downstream_exception() -> None:
    """
    First request raises 500 inside the app; middleware must release the lock
    so the concurrent follower doesn't stall until TTL.
    """
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        async def call():
            return await ac.post("/boom", headers={"X-Idempotency-Key": "E"})

        r1, r2 = await asyncio.gather(call(), call())
        assert r1.status_code == r2.status_code == 500

        meta = await store.meta("E")
        # Lock must be cleared after the exception path
        assert meta.get("lock") is False
        assert meta.get("state") is None or meta.get("state") != "in_progress"


@pytest.mark.asyncio
async def test_non_cached_large_body_releases_lock() -> None:
    """
    Body larger than max_body -> leader does not cache and must release lock.
    Two concurrent calls should both return 200 and "replayed" must be false.
    """
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
        max_body=16,  # tiny
        cache_streaming=False,
        tenant_provider=lambda scope: "test",
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        big_body = {"x": "y" * 64}  # definitely >16 bytes serialized

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
