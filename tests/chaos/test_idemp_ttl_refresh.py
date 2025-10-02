from __future__ import annotations

import asyncio
import json
from typing import Any, MutableMapping

import pytest
from starlette.types import Scope

from app import settings as settings_module
from app.middleware.idempotency import IdempotencyMiddleware
from app.settings import get_settings
from tests.testlib.fake_idem_store import RecordingStore

pytestmark = pytest.mark.asyncio


def _make_app():
    async def app(scope: Scope, receive: Any, send: Any) -> None:
        body = json.dumps({"ok": True}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send(
            {"type": "http.response.start", "status": 200, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})

    return app


def _http_scope(key: str) -> Scope:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/do",
        "headers": [(b"x-idempotency-key", key.encode())],
    }  # type: ignore[return-value]


@pytest.fixture(autouse=True)
def _enforce_mode(monkeypatch: pytest.MonkeyPatch):
    eff = get_settings("test")
    eff.idempotency.mode = "enforce"
    settings_module.settings = eff
    yield


async def _run(mid: IdempotencyMiddleware, scope: Scope):
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    out: list[MutableMapping[str, Any]] = []

    async def send(message: MutableMapping[str, Any]) -> None:
        out.append(message)

    await mid(scope, receive, send)
    start = next(m for m in out if m["type"] == "http.response.start")
    return {k.decode(): v.decode() for k, v in start["headers"]}


async def test_touch_on_replay_refreshes_ttl(monkeypatch):
    key = "ttl-key"
    store = RecordingStore()
    mid = IdempotencyMiddleware(
        app=_make_app(),
        store=store,
        methods=("POST",),
        wait_budget_ms=500,
        jitter_ms=10,
        strict_fail_closed=False,
        touch_on_replay=True,
        ttl_s=1,
    )

    await _run(mid, _http_scope(key))
    await asyncio.sleep(0.2)
    _ = await _run(mid, _http_scope(key))
    assert store.touch_calls.get(key, 0) >= 1
