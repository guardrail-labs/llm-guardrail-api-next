import hashlib
import time

import pytest

from app.idempotency.memory_store import MemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import StoredResponse


@pytest.mark.asyncio
async def test_memory_store_inspect_and_purge() -> None:
    store = MemoryIdemStore(tenant="tenant-mem", recent_limit=10)
    key = "memory-key"

    ok, owner = await store.acquire_leader(key, 5, "abcdef123456")
    assert ok and owner

    pending = await store.inspect(key)
    assert pending["state"] == "in_progress"
    assert pending["payload_fingerprint_prefix"] == "abcdef12"

    body = b"{\"ok\": true}"
    body_fp = hashlib.sha256(body).hexdigest()
    await store.put(
        key,
        StoredResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=body,
            content_type="application/json",
            stored_at=time.time(),
            replay_count=0,
            body_sha256=body_fp,
        ),
        ttl_s=30,
    )

    snapshot = await store.inspect(key)
    assert snapshot["state"] == "stored"
    assert snapshot["size_bytes"] == len(body)
    assert snapshot["replay_count"] == 0
    assert snapshot["content_type"] == "application/json"
    assert snapshot["payload_fingerprint_prefix"] == body_fp[:8]
    assert snapshot["first_seen_at"] <= snapshot["last_seen_at"]

    recent = await store.list_recent(limit=5)
    assert recent
    assert recent[-1][0] == key

    purged = await store.purge(key)
    assert purged is True
    after = await store.inspect(key)
    assert after["state"] == "missing"


@pytest.mark.asyncio
async def test_redis_store_inspect_and_recent_order() -> None:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis()
    await redis.flushall()

    store = RedisIdemStore(redis, ns="idem-test", tenant="tenant-r", recent_limit=5)
    key = "redis-key"
    ok, owner = await store.acquire_leader(key, 5, "deadbeefcafebabe")
    assert ok and owner

    pending = await store.inspect(key)
    assert pending["state"] == "in_progress"
    assert pending["payload_fingerprint_prefix"] == "deadbeef"

    body = b"redis"
    body_fp = hashlib.sha256(body).hexdigest()
    await store.put(
        key,
        StoredResponse(
            status=201,
            headers={"content-type": "text/plain"},
            body=body,
            content_type="text/plain",
            stored_at=time.time(),
            replay_count=1,
            body_sha256=body_fp,
        ),
        ttl_s=60,
    )

    stored = await store.inspect(key)
    assert stored["state"] == "stored"
    assert stored["payload_fingerprint_prefix"] == body_fp[:8]
    assert stored["size_bytes"] == len(body)
    assert stored["replay_count"] == 1

    # Populate a few additional keys to exercise ordering/cap.
    for idx in range(3):
        other = f"redis-extra-{idx}"
        ok, owner = await store.acquire_leader(other, 5, f"finger-{idx}")
        assert ok and owner
        await store.put(
            other,
            StoredResponse(
                status=200,
                headers={},
                body=b"x",
                content_type=None,
                stored_at=time.time(),
                replay_count=0,
                body_sha256=hashlib.sha256(b"x").hexdigest(),
            ),
            ttl_s=5,
        )

    recent = await store.list_recent(limit=3)
    assert len(recent) == 3
    # list_recent returns newest first; the last inserted extra key should be first.
    assert recent[0][0] == "redis-extra-2"

    purged = await store.purge(key)
    assert purged is True
    after = await store.inspect(key)
    assert after["state"] == "missing"
