"""Runtime dependency helpers for shared infrastructure."""

from __future__ import annotations

from typing import Optional

from redis.asyncio import from_url as redis_from_url

from app import settings
from app.idempotency.redis_store import RedisIdemStore
from app.idempotency.store import IdemStore

_redis = None
_store: Optional[IdemStore] = None


def redis_client():
    global _redis
    if _redis is None:
        _redis = redis_from_url(settings.IDEMP_REDIS_URL, decode_responses=False)
    return _redis


def idem_store() -> IdemStore:
    global _store
    if _store is None:
        _store = RedisIdemStore(
            redis_client(),
            ns=settings.IDEMP_REDIS_NAMESPACE,
            tenant="default",
            recent_limit=settings.IDEMP_RECENT_ZSET_MAX,
        )
    return _store
