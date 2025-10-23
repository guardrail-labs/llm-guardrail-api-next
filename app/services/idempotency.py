from __future__ import annotations

from typing import Optional

from redis.asyncio import Redis

from app.services.redis_runtime import get_redis


class IdempotencyStore:
    def __init__(self, redis: Optional[Redis] = None) -> None:
        self.redis = redis or get_redis()

    async def reserve(self, key: str, ttl_s: int) -> bool:
        return bool(await self.redis.set(f"idem:{key}", "1", nx=True, ex=ttl_s))

    async def touch_and_get(self, key: str, ttl_s: int) -> bool:
        async with self.redis.pipeline(transaction=False) as pipe:
            pipe.exists(f"idem:{key}")
            pipe.expire(f"idem:{key}", ttl_s)
            exists, _ = await pipe.execute()
        return bool(exists)
