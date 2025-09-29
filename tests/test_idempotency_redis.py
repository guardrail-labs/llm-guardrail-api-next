import time

import pytest
from fakeredis.aioredis import FakeRedis

from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import StoredResponse

pytestmark = pytest.mark.asyncio


async def test_store_put_get_roundtrip():
    redis = FakeRedis()
    store = RedisIdemStore(redis, ns="idem", tenant="t1")
    key = "abc123"
    assert await store.acquire_leader(key, 5, "fp")
    resp = StoredResponse(
        status=200,
        headers={
            "content-type": "application/json",
            "x-frame-options": "DENY",
            "x-extra": "ignored",
        },
        body=b'{"ok":true}',
        content_type="application/json",
    )
    await store.put(key, resp, 5)
    cached = await store.get(key)
    assert cached is not None
    assert cached.status == 200
    assert cached.body == b'{"ok":true}'
    meta = await store.meta(key)
    assert meta["state"] == "stored"


async def test_single_flight_locking():
    redis = FakeRedis()
    store = RedisIdemStore(redis, tenant="t")
    key = "k"
    assert await store.acquire_leader(key, 2, "fp1")
    assert not await store.acquire_leader(key, 2, "fp2")
    await store.release(key)
    assert await store.acquire_leader(key, 2, "fp3")


async def test_ttl_expiry_allows_new_value():
    redis = FakeRedis()
    store = RedisIdemStore(redis, tenant="t")
    key = "k2"
    await store.acquire_leader(key, 1, "fp")
    await store.put(key, StoredResponse(status=200, headers={}, body=b"v1"), 1)
    assert (await store.get(key)).body == b"v1"
    time.sleep(1.1)
    assert await store.get(key) is None
