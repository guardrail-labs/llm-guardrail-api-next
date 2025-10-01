from typing import Any, Dict

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.idempotency.memory_store import MemoryIdemStore
from app.middleware.idempotency import IdempotencyMiddleware


@pytest.mark.asyncio
async def test_env_defaults_methods_ttl_max_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDEMP_METHODS", "post, put")
    monkeypatch.setenv("IDEMP_TTL_SECONDS", "7")
    monkeypatch.setenv("IDEMP_MAX_BODY_BYTES", "32")

    app = FastAPI()
    store = MemoryIdemStore()

    @app.post("/echo")
    async def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "payload": payload}

    # Do not pass methods/ttl/max_body -> pick from env
    app.add_middleware(
        IdempotencyMiddleware,
        store=store,
        cache_streaming=False,
        tenant_provider=lambda scope: "test",
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as ac:
        # POST is allowed by env config
        r1 = await ac.post("/echo", json={"x": 1}, headers={"X-Idempotency-Key": "K"})
        assert r1.status_code == 200
        assert r1.headers.get("idempotency-replayed") == "false"

        # Body > max_body -> not cached -> second call is not a replay (false)
        big = {"x": "y" * 64}
        r2 = await ac.post("/echo", json=big, headers={"X-Idempotency-Key": "K2"})
        assert r2.status_code == 200
        assert r2.headers.get("idempotency-replayed") == "false"
