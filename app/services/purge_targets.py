from __future__ import annotations

from typing import Dict, List, Protocol

from redis.asyncio import Redis

from app.services.retention import Resource


class PurgeTarget(Protocol):
    async def list_expired(self, tenant: str, now: float, limit: int) -> List[str]:
        ...

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        ...


class RedisZsetTarget(PurgeTarget):
    def __init__(self, redis: Redis, resource: Resource) -> None:
        self._redis = redis
        self._resource = resource

    def _index_key(self, tenant: str) -> str:
        return f"retention:index:{self._resource.value}:{tenant}"

    async def list_expired(self, tenant: str, now: float, limit: int) -> List[str]:
        if limit <= 0:
            return []
        key = self._index_key(tenant)
        ids = await self._redis.zrangebyscore(key, "-inf", now, start=0, num=limit)
        return [
            item.decode("utf-8") if isinstance(item, bytes) else str(item)
            for item in ids
        ]

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        if not ids:
            return 0
        key = self._index_key(tenant)
        pipe = self._redis.pipeline()
        for item in ids:
            pipe.zrem(key, item)
        await pipe.execute()
        return len(ids)


class RedisDLQMessages(RedisZsetTarget):
    def __init__(self, redis: Redis) -> None:
        super().__init__(redis, Resource.DLQ_MSG)

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        if not ids:
            return 0
        key_prefix = "dlq:msg:"
        pipe = self._redis.pipeline()
        for item in ids:
            pipe.delete(f"{key_prefix}{item}")
        await pipe.execute()
        removed = await super().purge_ids(tenant, ids)
        return removed


class RedisIdempotency(RedisZsetTarget):
    def __init__(self, redis: Redis) -> None:
        super().__init__(redis, Resource.IDEMP_KEYS)

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        if not ids:
            return 0
        pipe = self._redis.pipeline()
        for item in ids:
            pipe.delete(item)
        await pipe.execute()
        removed = await super().purge_ids(tenant, ids)
        return removed


class WebhookLogsRedis(RedisZsetTarget):
    def __init__(self, redis: Redis) -> None:
        super().__init__(redis, Resource.WEBHOOK_LOGS)

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        if not ids:
            return 0
        pipe = self._redis.pipeline()
        for item in ids:
            pipe.delete(item)
        await pipe.execute()
        removed = await super().purge_ids(tenant, ids)
        return removed


class AuditLogsSQL(PurgeTarget):
    async def list_expired(self, tenant: str, now: float, limit: int) -> List[str]:
        _ = (tenant, now, limit)
        return []

    async def purge_ids(self, tenant: str, ids: List[str]) -> int:
        _ = (tenant, ids)
        return 0


def build_registry(redis: Redis, *, include_sql: bool = False) -> Dict[str, PurgeTarget]:
    registry: Dict[str, PurgeTarget] = {
        Resource.DLQ_MSG.value: RedisDLQMessages(redis),
        Resource.IDEMP_KEYS.value: RedisIdempotency(redis),
        Resource.WEBHOOK_LOGS.value: WebhookLogsRedis(redis),
    }
    if include_sql:
        registry[Resource.AUDIT.value] = AuditLogsSQL()
    return registry


REGISTRY: Dict[str, PurgeTarget] = {}


__all__ = [
    "AuditLogsSQL",
    "PurgeTarget",
    "RedisDLQMessages",
    "RedisIdempotency",
    "WebhookLogsRedis",
    "build_registry",
    "REGISTRY",
]
