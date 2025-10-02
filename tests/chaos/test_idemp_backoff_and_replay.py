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


def _make_app(counter: dict[str, int], delay: float = 0.0):
    async def app(scope: Scope, receive: Any, send: Any) -> None:
        counter["calls"] = counter.get("calls", 0) + 1
        if delay:
            await asyncio.sleep(delay)
        body = json.dumps({"ok": True, "n": counter["calls"]}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send(
            {"type": "http.response.start", "status": 200, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})

    return app


def _http_scope(
    method: str = "POST", path: str = "/do", headers: dict[str, str] | None = None
) -> Scope:
    hdrs = []
    if headers:
        for k, v in headers.items():
            hdrs.append((k.lower().encode(), v.encode()))
    return {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "headers": hdrs,
    }  # type: ignore[return-value]


async def _collect(send_msgs: list[MutableMapping[str, Any]], message):
    send_msgs.append(message)


async def _recv_empty():
    return {"type": "http.request", "body": b"", "more_body": False}


@pytest.fixture(autouse=True)
def _enforce_mode(monkeypatch: pytest.MonkeyPatch):
    eff = get_settings("test")
    eff.idempotency.mode = "enforce"
    settings_module.settings = eff
    yield


async def _run_once(mid: IdempotencyMiddleware, scope: Scope):
    sent: list[MutableMapping[str, Any]] = []
    await mid(scope, _recv_empty, lambda m: _collect(sent, m))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = next(m for m in sent if m["type"] == "http.response.body")
    status = start["status"]
    headers = {k.decode(): v.decode() for k, v in start["headers"]}
    payload = json.loads((body.get("body") or b"{}").decode() or "{}")
    return status, headers, payload


async def _concurrent(mid: IdempotencyMiddleware, n: int, scope_factory):
    results = await asyncio.gather(
        *[_run_once(mid, scope_factory()) for _ in range(n)]
    )
    return results


async def test_single_leader_multiple_followers_replay(monkeypatch):
    key = "abc123"
    headers = {"x-idempotency-key": key}
    store = RecordingStore()
    calls: dict[str, int] = {}

    mid = IdempotencyMiddleware(
        app=_make_app(calls),
        store=store,
        methods=("POST",),
        wait_budget_ms=2000,
        jitter_ms=10,
        strict_fail_closed=False,
        cache_streaming=False,
        touch_on_replay=True,
    )

    def scope_factory() -> Scope:
        return _http_scope(headers=headers)

    results = await _concurrent(mid, 8, scope_factory)

    bodies = {json.dumps(r[2], sort_keys=True) for r in results}
    assert len(bodies) == 1
    assert calls["calls"] == 1

    replayed = [r for r in results if r[1].get("idempotency-replayed") == "true"]
    assert len(replayed) == 7
    counts = [int(r[1].get("idempotency-replay-count", "0")) for r in results]
    assert max(counts) >= 6

    assert store.touch_calls.get(key, 0) >= 1


async def test_wait_budget_timeout_falls_back_to_fresh(monkeypatch):
    key = "hang"
    headers = {"x-idempotency-key": key}
    store = RecordingStore()
    calls: dict[str, int] = {}
    mid = IdempotencyMiddleware(
        app=_make_app(calls, delay=0.2),
        store=store,
        methods=("POST",),
        wait_budget_ms=50,
        jitter_ms=5,
        strict_fail_closed=False,
    )

    orig_wait = mid._wait_for_release_or_value

    async def wait_with_budget(key: str, timeout: float) -> str:
        budget = (mid.wait_budget_ms or int(timeout * 1000)) / 1000.0
        return await orig_wait(key, min(timeout, budget))

    mid._wait_for_release_or_value = wait_with_budget  # type: ignore[assignment]

    async def leader():
        return await _run_once(mid, _http_scope(headers=headers))

    async def follower():
        await asyncio.sleep(0.01)
        return await _run_once(mid, _http_scope(headers=headers))

    s1, s2 = await asyncio.gather(leader(), follower())

    assert s1[1].get("idempotency-replayed") == "false"
    assert s2[1].get("idempotency-replayed") == "false"
    assert calls["calls"] == 2
