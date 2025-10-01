from __future__ import annotations

import asyncio

import pytest

from app.idempotency.redis_store import RedisIdemStore

try:
    from fakeredis.aioredis import FakeRedis as _FakeRedis
except Exception:  # pragma: no cover
    _FakeRedis = None  # fallback if fakeredis not available


@pytest.mark.asyncio
async def test_owner_token_enforced() -> None:
    if _FakeRedis is None:
        pytest.skip("fakeredis not installed")

    r = _FakeRedis(decode_responses=False)
    store = RedisIdemStore(r, tenant="t")

    ok, owner = await store.acquire_leader("k", 5, "fp1")
    assert ok and owner

    # Wrong owner cannot release
    rel_wrong = await store.release("k", owner="bad-owner")
    assert rel_wrong is False

    # Correct owner can release
    rel_ok = await store.release("k", owner=owner)
    assert rel_ok is True

    # Lock is gone now
    meta = await store.meta("k")
    assert meta.get("lock") is False
