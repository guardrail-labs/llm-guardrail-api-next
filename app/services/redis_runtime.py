from __future__ import annotations

import os
from typing import Optional

from redis.asyncio import Redis

_redis: Optional[Redis] = None


def get_redis() -> Redis:
    global _redis
    if _redis is None:
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _redis = Redis.from_url(url, encoding="utf-8", decode_responses=True)
    return _redis


class ScriptRegistry:
    def __init__(self) -> None:
        self.rate_token_sha: Optional[str] = None

    async def load(self, redis: Redis) -> None:
        script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill = tonumber(ARGV[2])
        local cost = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])
        local last = tonumber(redis.call('HGET', key, 'ts') or now)
        local tokens = tonumber(redis.call('HGET', key, 'tokens') or capacity)
        local elapsed = math.max(0, now - last)
        tokens = math.min(capacity, tokens + elapsed * refill)
        local allowed = 0
        if tokens >= cost then
          tokens = tokens - cost
          allowed = 1
        end
        redis.call('HSET', key, 'tokens', tokens, 'ts', now)
        redis.call('EXPIRE', key, 300)
        return {allowed, tokens}
        """
        self.rate_token_sha = await redis.script_load(script)


_scripts = ScriptRegistry()


async def runtime_warmup() -> None:
    redis = get_redis()
    await _scripts.load(redis)
