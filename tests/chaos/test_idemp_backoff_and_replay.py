from __future__ import annotations

import asyncio
import json
import time
from typing import Any, MutableMapping, Optional

import pytest
from starlette.types import Scope

from app import settings as settings_module
from app.middleware.idempotency import IdempotencyMiddleware
from app.settings import get_settings
from tests.utils.fake_idem_store import RecordingStore

pytestmark = pytest.mark.asyncio


def _make_app(counter: dict[str, int]):
    async def app(scope: Scope, receive: Any, send: Any) -> None:
        counter["calls"] = counter.get("calls", 0) + 1
        body = json.dumps({"ok": True, "n": counter["calls"]}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": headers,
            }
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
    # parse response
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
    # Given: same key & body; only one leader executes
    key = "abc123"
    headers = {"x-idempotency-key": key}
    store = RecordingStore()
    calls = {}

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

    # One execution (n==1), others replayed with same body
    bodies = {json.dumps(r[2], sort_keys=True) for r in results}
    assert len(bodies) == 1
    assert calls["calls"] == 1

    # All should have idempotency-replayed header; replay count grows
    replayed = [r for r in results if r[1].get("idempotency-replayed") == "true"]
    assert len(replayed) == 7
    counts = [int(r[1].get("idempotency-replay-count", "0")) for r in results]
    assert max(counts) >= 6  # approximate; depends on ordering

    # TTL touched at least once
    assert store.touch_calls.get(key, 0) >= 1


async def test_wait_budget_timeout_falls_back_to_fresh(monkeypatch):
    # Simulate never storing a value: leader keeps lock until wait budget expires.
    key = "hang"
    headers = {"x-idempotency-key": key}
    store = RecordingStore()
    calls: dict[str, int] = {}

    mid = IdempotencyMiddleware(
        app=_make_app(calls),
        store=store,
        methods=("POST",),
        wait_budget_ms=50,  # very small budget to force timeout path
        jitter_ms=5,
        strict_fail_closed=False,
        cache_streaming=False,
    )

    # Force short follower wait before timing out.
    mid.ttl_s = 0.05

    orig_acquire = store.acquire_leader

    async def stuck_acquire(key: str, ttl_s: int, body_fp: str):
        async with store._lock:
            entry = store._data.get(key)
            if entry and entry.owner:
                store.acquire_calls[key] = store.acquire_calls.get(key, 0) + 1
                return False, entry.owner
        ok, owner = await orig_acquire(key, ttl_s, body_fp)
        if ok:
            async with store._lock:
                entry = store._data.get(key)
                if entry:
                    entry.lock_expires_at = time.time() + 60.0
        return ok, owner

    async def stuck_put(key: str, value: Any, ttl_s: int) -> None:
        async with store._lock:
            entry = store._data.get(key)
            if entry:
                entry.ttl_expires_at = time.time() + float(ttl_s)

    async def stuck_release(key: str, owner: Optional[str] = None) -> None:
        return None

    store.acquire_leader = stuck_acquire  # type: ignore[assignment]
    store.put = stuck_put  # type: ignore[assignment]
    store.release = stuck_release  # type: ignore[assignment]

    # First request becomes leader but never persists or releases lock.
    s1 = await _run_once(mid, _http_scope(headers=headers))
    # Second request times out waiting and goes fresh.
    s2 = await _run_once(mid, _http_scope(headers=headers))

    # s1 is fresh; s2 can't replay (no value) and eventually returns fresh
    assert s1[1].get("idempotency-replayed") == "false"
    assert s2[1].get("idempotency-replayed") == "false"
    # Two downstream executions due to fallback
    assert calls["calls"] == 2
