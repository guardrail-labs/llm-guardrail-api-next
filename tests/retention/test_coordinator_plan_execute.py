from __future__ import annotations

import time

import pytest

from app.services.purge_coordinator import PurgeCoordinator
from app.services.purge_receipts import HmacSigner
from app.services.purge_targets import RedisDLQMessages
from app.services.retention import RedisRetentionStore, Resource, RetentionPolicy


@pytest.mark.asyncio
async def test_plan_execute_flow() -> None:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis(decode_responses=False)
    store = RedisRetentionStore(redis)
    policy = RetentionPolicy(
        tenant="acme",
        resource=Resource.DLQ_MSG,
        ttl_seconds=60,
        enabled=True,
    )
    await store.set_policy(policy)

    target = RedisDLQMessages(redis)
    signer = HmacSigner(b"secret", "test-kid")
    coordinator = PurgeCoordinator(
        redis,
        store,
        signer,
        {Resource.DLQ_MSG.value: target},
    )

    now = time.time()
    cutoff = now - 120
    index_key = "retention:index:dlq_msg:acme"
    await redis.zadd(index_key, {"old1": cutoff - 10, "old2": cutoff - 1, "new": now})
    await redis.set("dlq:msg:old1", b"payload1")
    await redis.set("dlq:msg:old2", b"payload2")

    planned = await coordinator.plan("acme", Resource.DLQ_MSG.value, now, limit=10)
    assert planned == ["old1", "old2"]

    dry_receipt = await coordinator.execute(
        "acme",
        Resource.DLQ_MSG.value,
        planned,
        dry_run=True,
        actor="tester",
        mode="manual",
    )
    assert dry_receipt.count == 0
    assert await redis.exists("dlq:msg:old1") == 1

    live_ids = await coordinator.plan("acme", Resource.DLQ_MSG.value, now, limit=10)
    live_receipt = await coordinator.execute(
        "acme",
        Resource.DLQ_MSG.value,
        live_ids,
        dry_run=False,
        actor="tester",
        mode="manual",
    )
    assert live_receipt.count == len(live_ids)
    assert await redis.exists("dlq:msg:old1") == 0
    stored = await coordinator.get_receipt(live_receipt.id)
    assert stored is not None
    assert stored[1].get("kid") == "test-kid"
    assert await coordinator.verify_receipt(live_receipt.id)
