from __future__ import annotations

import base64
import importlib
import inspect
from typing import Dict, Optional

from redis.asyncio import Redis, from_url as redis_from_url
from redis.asyncio.connection import BlockingConnectionPool

from app import settings
from app.idempotency.memory_store import InMemoryIdemStore, MemoryReservationStore
from app.idempotency.redis_store import RedisIdemStore, RedisReservationStore
from app.idempotency.store import IdempotencyStore, IdemStore
from app.services.dlq import DLQService
from app.services.purge_coordinator import PurgeCoordinator
from app.services.purge_receipts import Ed25519Signer, HmacSigner, Signer
from app.services.purge_targets import PurgeTarget, build_registry
from app.services.retention import (
    InMemoryRetentionStore,
    RedisRetentionStore,
    RetentionStore,
)

# Lazily initialized singletons for process lifetime.
_redis: Optional[Redis] = None
_store: Optional[IdemStore] = None
_redis_client: Optional[Redis] = None
_reservation_store: Optional[IdempotencyStore] = None
_dlq_service: Optional[DLQService] = None
_retention_store: Optional[RetentionStore] = None
_purge_signer: Optional[Signer] = None
_purge_targets: Optional[Dict[str, PurgeTarget]] = None
_purge_coordinator: Optional[PurgeCoordinator] = None


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
    if backend == "memory" and not settings.IDEMP_REDIS_URL.startswith("memory://"):
        backend = "redis"

    if backend == "redis":
        _reservation_store = RedisReservationStore(get_redis())
    else:
        _reservation_store = MemoryReservationStore()
    return _reservation_store


def get_dlq_service() -> DLQService:
    global _dlq_service
    if _dlq_service is None:
        _dlq_service = DLQService(get_redis())
    return _dlq_service


def get_retention_store() -> RetentionStore:
    global _retention_store
    if _retention_store is not None:
        return _retention_store

    if settings.REDIS_URL.startswith("memory://"):
        _retention_store = InMemoryRetentionStore()
    else:
        try:
            _retention_store = RedisRetentionStore(get_redis())
        except Exception:
            _retention_store = InMemoryRetentionStore()
    return _retention_store


def get_purge_signer() -> Signer:
    global _purge_signer
    if _purge_signer is not None:
        return _purge_signer

    key_id = settings.PURGE_KEY_ID
    ed_priv = settings.PURGE_ED25519_PRIV
    if ed_priv:
        _purge_signer = Ed25519Signer(ed_priv, key_id)
        return _purge_signer

    secret = base64.b64decode(settings.PURGE_SIGNING_SECRET)
    _purge_signer = HmacSigner(secret, key_id)
    return _purge_signer


def _get_purge_targets(redis: Redis) -> Dict[str, PurgeTarget]:
    global _purge_targets
    if _purge_targets is None:
        include_sql = bool(getattr(settings, "RETENTION_AUDIT_SQL_ENABLED", False))
        _purge_targets = build_registry(redis, include_sql=include_sql)
    return _purge_targets


def get_purge_coordinator() -> PurgeCoordinator:
    global _purge_coordinator
    if _purge_coordinator is not None:
        return _purge_coordinator

    redis = get_redis()
    store = get_retention_store()
    signer = get_purge_signer()
    targets = _get_purge_targets(redis)
    _purge_coordinator = PurgeCoordinator(redis, store, signer, targets)
    return _purge_coordinator


async def close_redis_connections() -> None:
    global _redis_client, _redis, _dlq_service
    global _retention_store, _purge_signer, _purge_targets, _purge_coordinator

    client_main = _redis_client
    legacy_client = _redis

    _redis_client = None
    _redis = None
    _dlq_service = None
    _retention_store = None
    _purge_signer = None
    _purge_targets = None
    _purge_coordinator = None

    await _close_client(client_main)
    await _close_client(legacy_client)


async def _close_client(client: Optional[Redis]) -> None:
    if client is None:
        return
    try:
        await client.close()
    except Exception:
        pass
    pool = getattr(client, "connection_pool", None)
    if pool is None:
        return
    disconnect = getattr(pool, "disconnect", None)
    if callable(disconnect):
        try:
            result = disconnect(inuse_connections=True)
        except TypeError:
            result = disconnect()
        if inspect.isawaitable(result):
            await result


router = importlib.import_module("app.runtime.router")
