from __future__ import annotations

import os
import time

import pytest
from redis.asyncio import Redis

from app.webhooks.dlq import DeadLetterQueue
from app.webhooks.models import WebhookJob
from app.webhooks.retry import RetryQueue, compute_backoff_s

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@pytest.mark.asyncio
async def test_backoff_increases_with_attempt_and_jitter() -> None:
    b1 = compute_backoff_s(1.0, 2.0, 1, 0.0)
    b2 = compute_backoff_s(1.0, 2.0, 2, 0.0)
    b3 = compute_backoff_s(1.0, 2.0, 3, 0.0)
    assert b1 == 1.0 and b2 == 2.0 and b3 == 4.0


@pytest.mark.asyncio
async def test_retry_then_dlq_roundtrip() -> None:
    try:
        redis = Redis.from_url(REDIS_URL)
        await redis.ping()
    except Exception:
        pytest.skip("Redis not available")
        return

    retry_queue = RetryQueue(redis, prefix="twh")
    dlq = DeadLetterQueue(redis, prefix="twh")

    await redis.delete("twh:schedule")
    await redis.delete("twh:dlq")

    job = WebhookJob(
        url="https://example.invalid/hook",
        method="POST",
        headers={},
        body=b"{}",
        attempt=1,
        created_at_s=time.time(),
        last_error=None,
    )

    await retry_queue.enqueue(job, due_at_s=time.time())
    _, jobs = await retry_queue.pop_ready(limit=10)
    assert len(jobs) == 1
    popped = jobs[0]
    assert popped.attempt == 1

    for attempt in range(1, 6):
        if attempt >= 5:
            await dlq.push(popped)
        else:
            await retry_queue.enqueue(
                WebhookJob(
                    url=popped.url,
                    method=popped.method,
                    headers=popped.headers,
                    body=popped.body,
                    attempt=attempt + 1,
                    created_at_s=popped.created_at_s,
                    last_error="fail",
                ),
                due_at_s=time.time(),
            )

    assert await dlq.size() == 1
    peeked = await dlq.peek(1)
    assert peeked and peeked[0].attempt == 5

    moved = await dlq.replay(retry_queue, limit=1, now_s=time.time())
    assert moved == 1
    assert await dlq.size() == 0

    await redis.delete("twh:schedule")
    await redis.delete("twh:dlq")
    await redis.aclose()
    await redis.connection_pool.disconnect()
