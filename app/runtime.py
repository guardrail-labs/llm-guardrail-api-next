from __future__ import annotations

from typing import Optional

from redis.asyncio import Redis, from_url as redis_from_url
from redis.asyncio.connection import BlockingConnectionPool

from app.idempotency.memory_store import InMemoryIdemStore, MemoryReservationStore
from app.idempotency.redis_store import RedisIdemStore, RedisReservationStore
from app.idempotency.store import IdemStore, IdempotencyStore
from app import settings

_redis = None
_store: IdemStore | None = None
_redis_client: Optional[Redis] = None
_reservation_store: Optional[IdempotencyStore] = None


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
        backend = settings.IDEMPOTENCY_BACKEND or "memory"
        if backend not in {"memory", "redis"}:
            backend = "memory"
        if (
            backend == "memory"
            and not settings.IDEMP_REDIS_URL.startswith("memory://")
        ):
            backend = "redis"
        if backend == "redis":
            _store = RedisIdemStore(
                redis_client(),
                ns=settings.IDEMP_REDIS_NAMESPACE,
                tenant="default",
                recent_limit=settings.IDEMP_RECENT_ZSET_MAX,
            )
        else:
            _store = InMemoryIdemStore(recent_limit=settings.IDEMP_RECENT_ZSET_MAX)
    return _store


def get_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        pool = BlockingConnectionPool.from_url(
            settings.REDIS_URL,
            timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT_S,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT_S,
            health_check_interval=settings.REDIS_HEALTHCHECK_INTERVAL_S,
            max_connections=50,
        )
        _redis_client = Redis(connection_pool=pool)
    return _redis_client


def get_idempotency_store() -> IdempotencyStore:
    global _reservation_store
    if _reservation_store is not None:
        return _reservation_store

    backend = settings.IDEMPOTENCY_BACKEND or "memory"
    if backend not in {"memory", "redis"}:
        backend = "memory"

    if backend == "redis":
        _reservation_store = RedisReservationStore(get_redis())
    else:
        _reservation_store = MemoryReservationStore()
    return _reservation_store
