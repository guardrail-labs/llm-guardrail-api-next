from __future__ import annotations

import math
import random
import time
from typing import Awaitable, List, Optional, Tuple, cast

from redis.asyncio import Redis

from app.webhooks.models import WebhookJob


def _k(prefix: str, name: str) -> str:
    return f"{prefix}:{name}"


def _now() -> float:
    return time.time()


def compute_backoff_s(base_s: float, factor: float, attempt: int, jitter_s: float) -> float:
    expo = base_s * math.pow(factor, max(0, attempt - 1))
    jitter = random.uniform(0.0, jitter_s)
    return float(expo + jitter)


class RetryQueue:
    """
    Redis-based delayed retry queue using a ZSET schedule.
    Members are JSON-encoded WebhookJob. Score is unix timestamp due_at.
    """

    def __init__(self, redis: Redis, prefix: str = "whq") -> None:
        self._redis = redis
        self._prefix = prefix

    @property
    def redis(self) -> Redis:
        return self._redis

    @property
    def prefix(self) -> str:
        return self._prefix

    def _schedule_key(self) -> str:
        return _k(self._prefix, "schedule")

    def schedule_key(self) -> str:
        return self._schedule_key()

    async def enqueue(self, job: WebhookJob, due_at_s: float) -> None:
        await cast(
            Awaitable[int],
            self._redis.zadd(self._schedule_key(), {job.to_json(): float(due_at_s)}),
        )

    async def enqueue_raw(self, raw_json: str, due_at_s: float) -> None:
        await cast(
            Awaitable[int],
            self._redis.zadd(self._schedule_key(), {raw_json: float(due_at_s)}),
        )

    async def pop_ready(self, limit: int = 10) -> Tuple[float, List[WebhookJob]]:
        now = _now()
        key = self._schedule_key()
        entries = await cast(
            Awaitable[list[bytes]],
            self._redis.zrangebyscore(key, min=-1, max=now, start=0, num=limit),
        )
        if not entries:
            return now, []
        await cast(Awaitable[int], self._redis.zrem(key, *entries))
        jobs = [WebhookJob.from_json(entry.decode("utf-8")) for entry in entries]
        return now, jobs

    async def earliest_due_ts(self) -> Optional[float]:
        items = await cast(
            Awaitable[List[Tuple[bytes, float]]],
            self._redis.zrange(self._schedule_key(), 0, 0, withscores=True),
        )
        if not items:
            return None
        return float(items[0][1])

    async def size(self) -> int:
        size = await cast(Awaitable[int], self._redis.zcard(self._schedule_key()))
        return int(size)
