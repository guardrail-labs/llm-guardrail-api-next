from typing import Any

import pytest

from app.idempotency.memory_store import MemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore

try:
    from fakeredis.aioredis import FakeRedis as _FakeRedis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    _FakeRedis = None  # noqa: N816


@pytest.mark.asyncio
async def test_memory_store_owner_release() -> None:
    store = MemoryIdemStore()
    ok, owner = await store.acquire_leader("k", 5, "fp1")
    assert ok and owner
    # Wrong owner cannot release
    rel = await store.release("k", owner="someone-else")
    assert rel is False
    # Right owner releases
    rel2 = await store.release("k", owner=owner)
    assert rel2 is True
    meta = await store.meta("k")
    assert meta.get("lock") is False or meta.get("lock") is None
    assert meta.get("state") is None or meta.get("state") != "in_progress"


@pytest.mark.asyncio
@pytest.mark.skipif(_FakeRedis is None, reason="fakeredis not installed")
async def test_redis_store_owner_release() -> None:
    r: Any = _FakeRedis(decode_responses=False)
    store = RedisIdemStore(r, ns="t", tenant="acme", recent_limit=100)
    ok, owner = await store.acquire_leader("k", 5, "fp1")
    assert ok and owner
    # Wrong owner cannot release
    rel = await store.release("k", owner="bad-owner")
    assert rel is False
    # Right owner releases
    rel2 = await store.release("k", owner=owner)
    assert rel2 is True
    meta = await store.meta("k")
    assert meta.get("lock") is False or meta.get("lock") is None
    assert meta.get("state") is None or meta.get("state") != "in_progress"
