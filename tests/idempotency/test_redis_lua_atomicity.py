import asyncio
from typing import Any

import pytest

# Make typing tolerant whether fakeredis is installed or not.
try:
    from fakeredis.aioredis import FakeRedis as _FakeRedis
except Exception:  # pragma: no cover
    _FakeRedis = None  # runtime sentinel when fakeredis is absent

from app.idempotency.redis_store import RedisIdemStore

pytestmark = pytest.mark.skipif(_FakeRedis is None, reason="fakeredis not installed")


@pytest.mark.asyncio
async def test_lua_single_flight_atomic_acquire() -> None:
    # _FakeRedis is present due to skipif guard.
    r: Any = _FakeRedis(decode_responses=False)  # create aioredis-compatible client
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
