from __future__ import annotations

from typing import Dict

from redis.asyncio import Redis

from app.idempotency.store import IdempotencyStore, IdemStore
from app.services.dlq import DLQService
from app.services.purge_coordinator import PurgeCoordinator
from app.services.purge_receipts import Signer
from app.services.purge_targets import PurgeTarget
from app.services.retention import RetentionStore

from .router import GuardedRouter, GuardResponse, get_default_router

__all__ = [
    "GuardResponse",
    "GuardedRouter",
    "get_default_router",
    "redis_client",
    "idem_store",
    "get_redis",
    "get_idempotency_store",
    "get_dlq_service",
    "get_retention_store",
    "get_purge_signer",
    "get_purge_coordinator",
    "close_redis_connections",
]


def redis_client() -> Redis: ...


def idem_store() -> IdemStore: ...


def get_redis() -> Redis: ...


def get_idempotency_store() -> IdempotencyStore: ...


def get_dlq_service() -> DLQService: ...


def get_retention_store() -> RetentionStore: ...


def get_purge_signer() -> Signer: ...


def _get_purge_targets(redis: Redis) -> Dict[str, PurgeTarget]: ...


def get_purge_coordinator() -> PurgeCoordinator: ...


async def close_redis_connections() -> None: ...
