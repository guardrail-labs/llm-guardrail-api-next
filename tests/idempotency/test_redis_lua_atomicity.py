import asyncio

import pytest

try:
    from fakeredis.aioredis import FakeRedis as _FakeRedis
except Exception:  # pragma: no cover - allow skip if fakeredis not present
    _FakeRedis = None  # type: ignore[assignment]

from app.idempotency.redis_store import RedisIdemStore


pytestmark = pytest.mark.skipif(_FakeRedis is None, reason="fakeredis not installed")


@pytest.mark.asyncio
async def test_lua_single_flight_atomic_acquire() -> None:
    r = _FakeRedis(decode_responses=False)  # type: ignore[operator]
    store = RedisIdemStore(r, ns="t", tenant="acme", recent_limit=100)

    async def attempt() -> bool:
        return await store.acquire_leader("K", 10, "fp-1")

    # Run concurrently; exactly one must acquire.
    results = await asyncio.gather(*[attempt(), attempt(), attempt()])
    assert sum(1 for x in results if x) == 1

    # State visible immediately
    meta = await store.meta("K")
    assert meta.get("state") == "in_progress"
    assert meta.get("lock") is True
