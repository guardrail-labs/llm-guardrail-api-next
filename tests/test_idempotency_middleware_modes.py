from typing import Any, Optional

import pytest

from app.idempotency.store import StoredResponse
from app.middleware.idempotency import IdempotencyMiddleware
from app.settings import get_settings


class _StubStore:
    async def acquire_leader(
        self, key: str, ttl_s: int, body_fp: str
    ) -> tuple[bool, Optional[str]]:
        return True, "owner"

    async def release(self, key: str, owner: Optional[str] = None) -> None:
        return None

    async def get(self, key: str) -> Optional[StoredResponse]:
        return None

    async def put(self, key: str, value: StoredResponse, ttl_s: int) -> None:
        return None

    async def meta(self, key: str) -> dict[str, Any]:
        return {}

    async def bump_replay(self, key: str) -> Optional[int]:
        return 0

    async def touch(self, key: str, ttl_s: int) -> None:
        return None


@pytest.mark.asyncio
async def test_middleware_passthrough_without_idempotency(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [
        "APP_ENV",
        "IDEMPOTENCY_MODE",
        "IDEMPOTENCY_ENFORCE_METHODS",
        "IDEMPOTENCY_LOCK_TTL_S",
    ]:
        monkeypatch.delenv(name, raising=False)

    settings = get_settings("dev")

    events: list[str] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        events.append(scope["method"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = IdempotencyMiddleware(
        app,
        _StubStore(),
        ttl_s=settings.idempotency.lock_ttl_s,
        methods=settings.idempotency.enforce_methods,
        wait_budget_ms=settings.idempotency.wait_budget_ms,
        jitter_ms=settings.idempotency.jitter_ms,
        strict_fail_closed=settings.idempotency.strict_fail_closed,
    )

    scope = {"type": "http", "method": "GET", "headers": []}

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await middleware(scope, receive, send)

    assert events == ["GET"]
    assert sent[-1]["body"] == b"ok"
