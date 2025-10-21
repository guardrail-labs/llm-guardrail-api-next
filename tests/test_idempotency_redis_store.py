import os

import pytest
from redis.asyncio import Redis

from app.idempotency.redis_store import RedisReservationStore
from app.idempotency.store import IdempotencyResult

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@pytest.mark.asyncio
async def test_redis_reservation_store_flow() -> None:
    try:
        redis = Redis.from_url(REDIS_URL)
        await redis.ping()
    except Exception:
        pytest.skip("Redis not available for test")
        return

    store = RedisReservationStore(redis, prefix="testidem")
    key = "k1"
    fingerprint = "reqfp"
    ttl = 2

    await redis.delete("testidem:k1")

    ok_first = await store.begin(key, ttl, fingerprint)
    ok_second = await store.begin(key, ttl, fingerprint)
    assert ok_first is True
    assert ok_second is False

    pending = await store.get(key)
    assert pending is None

    payload = b'{"ok":true}'
    await store.finalize(key, payload, ttl)

    cached = await store.get(key)
    assert isinstance(cached, IdempotencyResult)
    assert cached.payload == payload

    await redis.delete("testidem:k1")
    await redis.close()
