from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from httpx import ASGITransport
from prometheus_client import REGISTRY
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.idempotency.memory_store import MemoryIdemStore
from app.middleware.idempotency import IdempotencyMiddleware


async def _echo(request):
    data = await request.json()
    payload = data if isinstance(data, dict) else {"body": data}
    return JSONResponse({"echo": payload, "ts": time.time()})


def _build_app(store: MemoryIdemStore, *, touch_on_replay: bool) -> Starlette:
    routes = [Route("/echo", _echo, methods=["POST"])]
    middleware = [
        Middleware(
            IdempotencyMiddleware,
            store=store,
            ttl_s=30,
            methods=("POST",),
            touch_on_replay=touch_on_replay,
            tenant_provider=lambda scope: "tenant-test",
        )
    ]
    return Starlette(routes=routes, middleware=middleware)


async def _post(client: httpx.AsyncClient, key: str, body: dict[str, object]) -> httpx.Response:
    return await client.post(
        "/echo",
        json=body,
        headers={"X-Idempotency-Key": key},
        timeout=5.0,
    )


async def test_replay_count_and_touch_refreshes_ttl() -> None:
    store = MemoryIdemStore(recent_limit=8, tenant="tenant-test")
    app = _build_app(store, touch_on_replay=True)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        key = "touch-key"
        first = await _post(client, key, {"value": 1})
        assert first.headers.get("Idempotency-Replayed") == "false"
        assert first.headers.get("Idempotency-Replay-Count") is None

        async with store._mu:  # type: ignore[attr-defined]
            stored_before_count = store._values[key][0].replay_count
            value_exp_before = store._values[key][1]
            state_exp_before = store._states[key][1]
            recent_before = list(store._recent)

        await asyncio.sleep(0.01)
        second = await _post(client, key, {"value": 1})
        assert second.headers.get("Idempotency-Replayed") == "true"
        assert second.headers.get("Idempotency-Replay-Count") == "1"
        assert second.headers.get("X-Idempotency-Key") == key

        async with store._mu:  # type: ignore[attr-defined]
            stored_after = store._values[key][0]
            value_exp_after = store._values[key][1]
            state_exp_after = store._states[key][1]
            recent_after = list(store._recent)

        assert stored_before_count == 0
        assert stored_after.replay_count == 1
        assert value_exp_after > value_exp_before
        assert state_exp_after > state_exp_before
        assert recent_after[-1][0] == key
        assert recent_after[-1][1] >= recent_before[-1][1]

        await asyncio.sleep(0.01)
        third = await _post(client, key, {"value": 1})
        assert third.headers.get("Idempotency-Replay-Count") == "2"

        async with store._mu:  # type: ignore[attr-defined]
            assert store._values[key][0].replay_count == 2


async def test_conflict_does_not_increment_replay_count() -> None:
    store = MemoryIdemStore(tenant="tenant-test")
    app = _build_app(store, touch_on_replay=False)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        key = "conflict-key"
        first = await _post(client, key, {"value": "one"})
        assert first.headers.get("Idempotency-Replayed") == "false"

        second = await _post(client, key, {"value": "two"})
        assert second.headers.get("Idempotency-Replayed") == "false"
        assert second.headers.get("Idempotency-Replay-Count") is None

        async with store._mu:  # type: ignore[attr-defined]
            assert store._values[key][0].replay_count == 0


def _sample_value(name: str, labels: dict[str, str]) -> float:
    value = REGISTRY.get_sample_value(name, labels)
    return float(value) if value is not None else 0.0


async def test_metrics_capture_replay_counts_and_touches() -> None:
    store = MemoryIdemStore(tenant="tenant-test")
    app = _build_app(store, touch_on_replay=True)

    tenant_labels = {"tenant": "tenant-test"}
    hist_labels = {"tenant": "tenant-test", "method": "POST"}
    before_sum = _sample_value("guardrail_idemp_replay_count_sum", hist_labels)
    before_count = _sample_value("guardrail_idemp_replay_count_count", hist_labels)
    before_touches = _sample_value("guardrail_idemp_touches_total", tenant_labels)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        key = "metrics-key"
        await _post(client, key, {"value": 7})
        await _post(client, key, {"value": 7})
        await _post(client, key, {"value": 7})

    after_sum = _sample_value("guardrail_idemp_replay_count_sum", hist_labels)
    after_count = _sample_value("guardrail_idemp_replay_count_count", hist_labels)
    after_touches = _sample_value("guardrail_idemp_touches_total", tenant_labels)

    assert after_sum - before_sum == pytest.approx(3.0)
    assert after_count - before_count == pytest.approx(2.0)
    assert after_touches - before_touches == pytest.approx(2.0)
