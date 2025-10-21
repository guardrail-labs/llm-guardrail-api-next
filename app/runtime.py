from __future__ import annotations

from typing import Optional

from redis.asyncio import Redis, from_url as redis_from_url
from redis.asyncio.connection import BlockingConnectionPool

from app import settings
from app.idempotency.memory_store import InMemoryIdemStore, MemoryReservationStore
from app.idempotency.redis_store import RedisIdemStore, RedisReservationStore
from app.idempotency.store import IdempotencyStore, IdemStore

# Lazily initialized singletons for process lifetime.
_redis: Optional[Redis] = None
_store: Optional[IdemStore] = None
_redis_client: Optional[Redis] = None
_reservation_store: Optional[IdempotencyStore] = None


def redis_client() -> Redis:
    """
    Return a simple Redis client built from IDEMP_REDIS_URL for legacy paths.
    Raises if memory URL is configured since that mode does not need Redis.
    """
    if settings.IDEMP_REDIS_URL.startswith("memory://"):
        raise RuntimeError("In-memory idempotency does not use redis_client()")

    global _redis
    if _redis is None:
        _redis = redis_from_url(settings.IDEMP_REDIS_URL, decode_responses=False)
    return _redis


def idem_store() -> IdemStore:
    """
    Factory for the primary idempotency store that maintains recent decision sets.
    Chooses Redis vs memory based on IDEMPOTENCY_BACKEND and IDEMP_REDIS_URL.
    """
    global _store
    if _store is not None:
        return _store

    backend = settings.IDEMPOTENCY_BACKEND or "memory"
    if backend not in {"memory", "redis"}:
        backend = "memory"

    # If backend says memory but a real Redis URL is present, prefer Redis.
    if backend == "memory" and not settings.IDEMP_REDIS_URL.startswith("memory://"):
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
    """
    Return a pooled Redis client for reservation/caching paths that use
    BlockingConnectionPool with explicit timeouts.
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    pool: BlockingConnectionPool = BlockingConnectionPool.from_url(
        settings.REDIS_URL,
        timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT_S,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT_S,
        health_check_interval=settings.REDIS_HEALTHCHECK_INTERVAL_S,
        max_connections=50,
    )
    _redis_client = Redis(connection_pool=pool)
    return _redis_client


def get_idempotency_store() -> IdempotencyStore:
    """
    Reservation-oriented idempotency factory.
    Fallback parity with idem_store(): if backend is "memory" but a real Redis
    URL is configured (not memory://), prefer Redis.
    """
    global _reservation_store
    if _reservation_store is not None:
        return _reservation_store

    backend = settings.IDEMPOTENCY_BACKEND or "memory"
    if backend not in {"memory", "redis"}:
        backend = "memory"

    # Prefer Redis when a non-memory Redis URL is configured.
    if backend == "memory" and not settings.IDEMP_REDIS_URL.startswith(
        "memory://"
    ):
        backend = "redis"

    if backend == "redis":
        _reservation_store = RedisReservationStore(get_redis())
    else:
        _reservation_store = MemoryReservationStore()
    return _reservation_store
