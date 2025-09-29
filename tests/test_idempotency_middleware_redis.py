import pytest
from fakeredis.aioredis import FakeRedis
from fastapi import FastAPI
from starlette.testclient import TestClient

from app.idempotency.redis_store import RedisIdemStore
from app.middleware.idempotency import IdempotencyMiddleware


def _app_factory(store):
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: dict):
        return payload

    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        ttl_s=2,
        methods=("POST", "PUT"),
        max_body=1024 * 1024,
        cache_streaming=False,
        tenant_provider=lambda scope: "default",
    )
    return app


@pytest.mark.asyncio
async def test_replay_header_set(event_loop):
    redis = FakeRedis()
    store = RedisIdemStore(redis)
    app = _app_factory(store)
    headers = {"X-Idempotency-Key": "abc123"}
    payload = {"ping": "pong"}
    with TestClient(app) as client:
        first = client.post("/echo", headers=headers, json=payload)
        assert first.status_code == 200
        assert first.json() == payload
        assert first.headers.get("idempotency-replayed") == "false"

        second = client.post("/echo", headers=headers, json=payload)
        assert second.headers.get("idempotency-replayed") == "true"
        assert second.json() == payload


@pytest.mark.asyncio
async def test_invalid_key_returns_400(event_loop):
    redis = FakeRedis()
    store = RedisIdemStore(redis)
    app = _app_factory(store)
    with TestClient(app) as client:
        resp = client.post("/echo", headers={"X-Idempotency-Key": "bad key!"}, json={"x": 1})
        assert resp.status_code == 400
        assert resp.json()["detail"] == "invalid idempotency key"
