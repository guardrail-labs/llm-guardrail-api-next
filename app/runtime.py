from __future__ import annotations

from redis.asyncio import from_url as redis_from_url

from app.idempotency.memory_store import InMemoryIdemStore
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import IdemStore
from app import settings

_redis = None
_store: IdemStore | None = None


def redis_client():
    if settings.IDEMP_REDIS_URL.startswith("memory://"):
        raise RuntimeError("In-memory idempotency store does not use redis_client()")
    global _redis
    if _redis is None:
        _redis = redis_from_url(settings.IDEMP_REDIS_URL, decode_responses=False)
    return _redis


def idem_store() -> IdemStore:
    global _store
    if _store is None:
        if settings.IDEMP_REDIS_URL.startswith("memory://"):
            _store = InMemoryIdemStore(recent_limit=settings.IDEMP_RECENT_ZSET_MAX)
        else:
            _store = RedisIdemStore(
                redis_client(),
                ns=settings.IDEMP_REDIS_NAMESPACE,
                tenant="default",
                recent_limit=settings.IDEMP_RECENT_ZSET_MAX,
            )
    return _store
