import asyncio
import hashlib
import time
from typing import Mapping

import pytest
from prometheus_client import REGISTRY

from app.idempotency.memory_store import MemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import StoredResponse


def _sample(name: str, labels: Mapping[str, str]) -> float:
    value = REGISTRY.get_sample_value(name, labels)
    return float(value) if value is not None else 0.0


@pytest.mark.asyncio
async def test_memory_inspect_touch_and_purge() -> None:
    store = MemoryIdemStore(tenant="tenant-memory", recent_limit=8)
    body = b"hello"
    fp = hashlib.sha256(body).hexdigest()

    await store.acquire_leader("mem-key", 2, fp)
    await store.put(
        "mem-key",
        StoredResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=body,
            content_type="application/json",
            stored_at=time.time(),
            replay_count=0,
            body_sha256=fp,
        ),
        ttl_s=2,
    )

    info = await store.inspect("mem-key")
    assert info["state"] == "stored"
    assert info["size_bytes"] == len(body)
    assert info["payload_fingerprint_prefix"] == fp[:8]
    assert info["first_seen_at"] > 0

    recent = await store.list_recent(limit=5)
    assert recent[0][0] == "mem-key"

    before_touch = _sample("guardrail_idemp_touches_total", {"tenant": "tenant-memory"})
    await asyncio.sleep(0.01)
    touched = await store.touch("mem-key", 5)
    after_touch = _sample("guardrail_idemp_touches_total", {"tenant": "tenant-memory"})
    assert touched is True
    assert after_touch == pytest.approx(before_touch + 1.0)

    refreshed = await store.inspect("mem-key")
    assert refreshed["expires_at"] > info["expires_at"]

    purged = await store.purge("mem-key")
    assert purged is True
    missing = await store.inspect("mem-key")
    assert missing["state"] == "missing"
    assert missing["first_seen_at"] == 0.0


@pytest.mark.asyncio
async def test_redis_inspect_touch_and_purge() -> None:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis(decode_responses=False)
    await redis.flushall()

    store = RedisIdemStore(redis, ns="idem-test", tenant="tenant-redis", recent_limit=16)
    body = b"{}"
    fp = hashlib.sha256(body).hexdigest()

    await store.acquire_leader("redis-key", 2, fp)
    await store.put(
        "redis-key",
        StoredResponse(
            status=201,
            headers={"content-type": "application/json"},
            body=body,
            content_type="application/json",
            stored_at=time.time(),
            replay_count=0,
            body_sha256=fp,
        ),
        ttl_s=2,
    )

    info = await store.inspect("redis-key")
    assert info["state"] == "stored"
    assert info["size_bytes"] == len(body)
    assert info["payload_fingerprint_prefix"] == fp[:8]
    assert info["first_seen_at"] > 0

    recent = await store.list_recent(limit=4)
    assert recent[0][0] == "redis-key"

    labels = {"tenant": "tenant-redis"}
    before_touch = _sample("guardrail_idemp_touches_total", labels)
    await asyncio.sleep(0.01)
    touched = await store.touch("redis-key", 5)
    after_touch = _sample("guardrail_idemp_touches_total", labels)
    assert touched is True
    assert after_touch == pytest.approx(before_touch + 1.0)

    refreshed = await store.inspect("redis-key")
    assert refreshed["expires_at"] > info["expires_at"]

    purged = await store.purge("redis-key")
    assert purged is True
    missing = await store.inspect("redis-key")
    assert missing["state"] == "missing"
