import asyncio
from typing import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from app.idempotency.memory_store import MemoryIdemStore
from app.middleware.idempotency import IdempotencyMiddleware
from app.admin import idem as admin_idem


@pytest.fixture
def memory_store() -> MemoryIdemStore:
    return MemoryIdemStore(recent_limit=100)


@pytest.fixture
def app_admin(
    memory_store: MemoryIdemStore, monkeypatch: pytest.MonkeyPatch
) -> FastAPI:
    """
    Minimal FastAPI app exposing only the admin idempotency endpoints.
    We monkeypatch runtime.idem_store() -> our memory_store to avoid Redis.
    """
    app = FastAPI()
    # monkeypatch the global accessor used by the admin router
    monkeypatch.setattr("app.admin.idem.idem_store", lambda: memory_store, raising=True)
    app.include_router(admin_idem.router)
    return app


@pytest.fixture
async def admin_client(app_admin: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app_admin, base_url="http://test") as ac:
        yield ac


def _build_core_app() -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: dict) -> dict:
        # Add a custom header via middleware capture; body is echoed
        return {"ok": True, "payload": payload}

    @app.post("/stream")
    async def stream_endpoint() -> asyncio.StreamReader:
        """
        Produce a streaming-style response at ASGI level:
        our middleware will see more_body=True at least once.
        Implemented in the raw ASGI app used by tests.
        """
        return asyncio.StreamReader()

    return app


@pytest.fixture
def app_with_idem(memory_store: MemoryIdemStore) -> FastAPI:
    """
    App with the idempotency middleware installed and two endpoints:
    - /echo: normal JSON (cacheable)
    - /stream: the test crafts streaming at ASGI level
    """
    app = _build_core_app()
    app.add_middleware(
        IdempotencyMiddleware,
        store=memory_store,
        ttl_s=60,
        methods=("POST",),
        max_body=1_000_000,
        cache_streaming=False,  # simulate "do not cache streaming"
        tenant_provider=lambda scope: "test",
    )
    return app


@pytest.fixture
async def idem_client(app_with_idem: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(app=app_with_idem, base_url="http://test") as ac:
        yield ac
