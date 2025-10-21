from __future__ import annotations

from typing import Awaitable, List, Optional, cast

from redis.asyncio import Redis

from app.webhooks.models import WebhookJob
from app.webhooks.retry import RetryQueue


def _k(prefix: str, name: str) -> str:
    return f"{prefix}:{name}"


class DeadLetterQueue:
    """
    DLQ using a Redis LIST in append-only fashion.
    Left side is oldest. Items are JSON-encoded WebhookJob.
    """

    def __init__(self, redis: Redis, prefix: str = "whq") -> None:
        self._redis = redis
        self._key = _k(prefix, "dlq")

    async def push(self, job: WebhookJob) -> None:
        await cast(Awaitable[int], self._redis.rpush(self._key, job.to_json()))

    async def peek(self, count: int = 20) -> List[WebhookJob]:
        raw = await cast(
            Awaitable[list[bytes]],
            self._redis.lrange(self._key, 0, max(0, count - 1)),
        )
        return [WebhookJob.from_json(item.decode("utf-8")) for item in raw]

    async def replay(self, retry_queue: RetryQueue, limit: int, now_s: float) -> int:
        moved = 0
        schedule_key = retry_queue.schedule_key()
        for _ in range(max(0, limit)):
            item = await cast(
                Awaitable[Optional[bytes]], self._redis.lpop(self._key)
            )
            if item is None:
                break
            await cast(Awaitable[int], self._redis.zadd(schedule_key, {item: now_s}))
            moved += 1
        return moved

    async def purge_older_than(self, threshold_s: float) -> int:
        raw = await cast(Awaitable[list[bytes]], self._redis.lrange(self._key, 0, -1))
        keep: list[bytes] = []
        removed = 0
        for item in raw:
            job = WebhookJob.from_json(item.decode("utf-8"))
            if job.created_at_s < threshold_s:
                removed += 1
            else:
                keep.append(item)
        if removed > 0:
            await cast(Awaitable[int], self._redis.delete(self._key))
            if keep:
                await cast(Awaitable[int], self._redis.rpush(self._key, *keep))
        return removed

    async def size(self) -> int:
        size = await cast(Awaitable[int], self._redis.llen(self._key))
        return int(size)
