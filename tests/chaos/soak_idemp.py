from __future__ import annotations

import asyncio
import json
import random
from typing import Any, MutableMapping

import pytest
from starlette.types import Scope

from app import settings as settings_module
from app.middleware.idempotency import IdempotencyMiddleware
from app.settings import get_settings
from tests.testlib.fake_idem_store import RecordingStore

pytestmark = pytest.mark.asyncio


def _app(counter: dict[str, int]):
    async def app(scope: Scope, receive: Any, send: Any) -> None:
        counter["n"] = counter.get("n", 0) + 1
        body = json.dumps({"seq": counter["n"]}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send(
            {"type": "http.response.start", "status": 200, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})

    return app


def _scope(key: str) -> Scope:
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


@pytest.mark.soak
async def test_soak_replays_and_conflicts():
    store = RecordingStore()
    calls: dict[str, int] = {}
    mid = IdempotencyMiddleware(
        app=_app(calls),
        store=store,
        methods=("POST",),
        wait_budget_ms=800,
        jitter_ms=20,
        strict_fail_closed=False,
        touch_on_replay=True,
    )

    keys = ["k-stable", "k-stable", "k-conflict-a", "k-conflict-b"]

    async def hit(key: str):
        await asyncio.sleep(random.random() * 0.02)
        sent: list[MutableMapping[str, Any]] = []

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m: MutableMapping[str, Any]):
            sent.append(m)

        await mid(_scope(key), recv, send)

    await asyncio.gather(*[hit(random.choice(keys)) for _ in range(50)])

    assert calls["n"] < 50
