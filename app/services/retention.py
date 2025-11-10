from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    cast,
    runtime_checkable,
)

from redis.asyncio import Redis


class Resource(str, Enum):
    AUDIT = "audit"
    DLQ_MSG = "dlq_msg"
    IDEMP_KEYS = "idemp_keys"
    WEBHOOK_LOGS = "webhook_logs"


@dataclass(slots=True)
class RetentionPolicy:
    tenant: str
    resource: Resource
    ttl_seconds: int
    enabled: bool = True


def expires_at(created_ts: float, ttl_seconds: int) -> float:
    ttl = max(int(ttl_seconds), 0)
    return created_ts + float(ttl)


@runtime_checkable
class RetentionStore(Protocol):
    async def get_policy(self, tenant: str, resource: str) -> Optional[RetentionPolicy]: ...

    async def set_policy(self, policy: RetentionPolicy) -> None: ...

    async def list_policies(self, tenant: Optional[str] = None) -> List[RetentionPolicy]: ...


class InMemoryRetentionStore(RetentionStore):
    def __init__(self) -> None:
        self._policies: Dict[tuple[str, str], RetentionPolicy] = {}

    async def get_policy(self, tenant: str, resource: str) -> Optional[RetentionPolicy]:
        key = (tenant, resource)
        return self._policies.get(key)

    async def set_policy(self, policy: RetentionPolicy) -> None:
        key = (policy.tenant, policy.resource.value)
        self._policies[key] = policy

    async def list_policies(self, tenant: Optional[str] = None) -> List[RetentionPolicy]:
        items = list(self._policies.values())
        if tenant is None:
            return sorted(items, key=lambda pol: (pol.tenant, pol.resource.value))
        return sorted(
            (pol for pol in items if pol.tenant == tenant),
            key=lambda pol: pol.resource.value,
        )


class RedisRetentionStore(RetentionStore):
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @staticmethod
    def _policy_key(tenant: str, resource: str) -> str:
        return f"retention:pol:{tenant}:{resource}"

    @staticmethod
    def _tenant_index_key(tenant: str) -> str:
        return f"retention:pol:tenant:{tenant}"

    @staticmethod
    def _encode(policy: RetentionPolicy) -> bytes:
        payload = {
            "tenant": policy.tenant,
            "resource": policy.resource.value,
            "ttl_seconds": int(policy.ttl_seconds),
            "enabled": bool(policy.enabled),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _decode(payload: bytes) -> RetentionPolicy:
        data = json.loads(payload.decode("utf-8"))
        resource_raw = str(data.get("resource", Resource.AUDIT.value))
        try:
            resource = Resource(resource_raw)
        except ValueError:
            resource = Resource.AUDIT
        return RetentionPolicy(
            tenant=str(data.get("tenant", "")),
            resource=resource,
            ttl_seconds=int(data.get("ttl_seconds", 0)),
            enabled=bool(data.get("enabled", True)),
        )

    async def get_policy(self, tenant: str, resource: str) -> Optional[RetentionPolicy]:
        key = self._policy_key(tenant, resource)
        raw = await self._redis.get(key)
        if raw is None:
            return None
        return self._decode(cast(bytes, raw))

    async def set_policy(self, policy: RetentionPolicy) -> None:
        key = self._policy_key(policy.tenant, policy.resource.value)
        await self._redis.set(key, self._encode(policy))
        await self._redis.sadd("retention:pol:tenants", policy.tenant)
        await self._redis.sadd(self._tenant_index_key(policy.tenant), policy.resource.value)

    async def list_policies(self, tenant: Optional[str] = None) -> List[RetentionPolicy]:
        if tenant is not None:
            return await self._list_for_tenant(tenant)
        tenants = await self._redis.smembers("retention:pol:tenants")
        items: List[RetentionPolicy] = []
        for tenant_raw in sorted(self._decode_bytes_set(tenants)):
            items.extend(await self._list_for_tenant(tenant_raw))
        return items

    async def _list_for_tenant(self, tenant: str) -> List[RetentionPolicy]:
        members = await self._redis.smembers(self._tenant_index_key(tenant))
        resources = sorted(self._decode_bytes_set(members))
        if not resources:
            return []
        pipe = self._redis.pipeline()
        for resource in resources:
            pipe.get(self._policy_key(tenant, resource))
        raw_items = await pipe.execute()
        policies: List[RetentionPolicy] = []
        for resource, raw in zip(resources, raw_items):
            if raw is None:
                continue
            policies.append(self._decode(cast(bytes, raw)))
        return policies

    @staticmethod
    def _decode_bytes_set(values: Iterable[bytes]) -> List[str]:
        decoded: List[str] = []
        for raw in values:
            if isinstance(raw, bytes):
                decoded.append(raw.decode("utf-8"))
            elif isinstance(raw, str):
                decoded.append(raw)
        return decoded


def _decisions_supports_sql() -> bool:
    try:
        import sqlalchemy  # noqa: F401

        from app.services import decisions as _decisions  # noqa: F401
    except Exception:  # pragma: no cover - optional dependency guard
        return False
    return True


def _cutoff_dt(cutoff_ms: int) -> datetime:
    cutoff = max(int(cutoff_ms), 0)
    return datetime.fromtimestamp(cutoff / 1000.0, tz=timezone.utc)


def _decision_matches(entry: Dict[str, Any], cutoff_ms: int) -> bool:
    try:
        ts = int(entry.get("ts_ms") or 0)
    except Exception:
        ts = 0
    return ts < cutoff_ms


def _iter_decision_items(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> Iterable[dict]:
    from app.services import decisions_store as store

    fetch = cast(
        Callable[..., Iterable[dict]],
        getattr(store, "_fetch_decisions_sorted_desc"),
    )
    try:
        items = fetch(
            tenant=tenant,
            bot=bot,
            limit=max(limit, 1),
            cursor=None,
            dir="next",
        )
    except TypeError:  # pragma: no cover - fallback for shims
        items = fetch(tenant=tenant, bot=bot)
    return list(items)


def count_decisions_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
) -> int:
    if _decisions_supports_sql():  # pragma: no branch - runtime check
        try:
            from sqlalchemy import and_, func, select

            from app.services import decisions as decisions_service

            table = decisions_service.decisions
            cutoff_dt = _cutoff_dt(cutoff_ms)
            conditions = [table.c.ts < cutoff_dt]
            if tenant:
                conditions.append(table.c.tenant == tenant)
            if bot:
                conditions.append(table.c.bot == bot)
            stmt = select(func.count()).select_from(table).where(and_(*conditions))
            with decisions_service._get_engine().begin() as conn:
                result = conn.execute(stmt).scalar_one()
            return int(result or 0)
        except Exception:
            pass

    count = 0
    for entry in _iter_decision_items(cutoff_ms, tenant=tenant, bot=bot, limit=50000):
        if _decision_matches(entry, cutoff_ms):
            count += 1
    return count


def delete_decisions_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> int:
    if limit <= 0:
        return 0

    if _decisions_supports_sql():
        try:
            from sqlalchemy import and_, delete, select

            from app.services import decisions as decisions_service

            table = decisions_service.decisions
            cutoff_dt = _cutoff_dt(cutoff_ms)
            conditions = [table.c.ts < cutoff_dt]
            if tenant:
                conditions.append(table.c.tenant == tenant)
            if bot:
                conditions.append(table.c.bot == bot)
            stmt = (
                select(table.c.id)
                .where(and_(*conditions))
                .order_by(table.c.ts.asc(), table.c.id.asc())
                .limit(limit)
            )
            with decisions_service._get_engine().begin() as conn:
                ids = [row.id for row in conn.execute(stmt)]
                if not ids:
                    return 0
                del_stmt = delete(table).where(table.c.id.in_(ids))
                result = conn.execute(del_stmt)
            return int(result.rowcount or 0)
        except Exception:
            pass

    from app.services import decisions_store as store

    items = list(
        _iter_decision_items(
            cutoff_ms,
            tenant=tenant,
            bot=bot,
            limit=max(limit * 2, 50000),
        )
    )
    survivors = []
    removed = 0
    for entry in items:
        if removed >= limit:
            survivors.append(entry)
            continue
        if _decision_matches(entry, cutoff_ms):
            removed += 1
        else:
            survivors.append(entry)
    setter = getattr(store, "_set_decisions_for_tests", None)
    if callable(setter):
        setter(survivors)
    return removed


def count_adjudications_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
) -> int:
    from app.observability import adjudication_log as log

    cutoff_dt = _cutoff_dt(cutoff_ms)
    try:
        _, total = log.paged_query(
            end=cutoff_dt,
            tenant=tenant,
            bot=bot,
            limit=0,
            offset=0,
            sort="ts_desc",
        )
        return int(total)
    except Exception:
        return 0


def delete_adjudications_before(
    cutoff_ms: int,
    *,
    tenant: Optional[str],
    bot: Optional[str],
    limit: int,
) -> int:
    if limit <= 0:
        return 0

    from app.observability import adjudication_log as log

    cutoff = cutoff_ms
    try:
        cap = int(getattr(log, "_CAP", 10000))
    except Exception:
        cap = 10000

    lock_obj = getattr(log, "_LOCK", None)

    def _compute_and_apply() -> int:
        snapshot_desc = []
        snapshot_fn = getattr(log, "_snapshot_records_desc", None)

        if callable(snapshot_fn):
            try:
                snapshot_desc = list(snapshot_fn())
            except Exception:
                snapshot_desc = []

        if not snapshot_desc:
            try:
                records, _ = log.paged_query(
                    tenant=None,
                    bot=None,
                    limit=cap,
                    offset=0,
                    sort="ts_asc",
                )
            except Exception:
                records = []
        else:
            records = list(reversed(snapshot_desc))

        kept = []
        removed = 0
        for record in records:
            ts_val = log._record_ts_ms(record) if hasattr(log, "_record_ts_ms") else 0
            match_tenant = tenant is None or getattr(record, "tenant", None) == tenant
            match_bot = bot is None or getattr(record, "bot", None) == bot
            if removed < limit and match_tenant and match_bot and ts_val < cutoff:
                removed += 1
                continue
            kept.append(record)

        if removed and hasattr(log, "clear") and hasattr(log, "append"):
            log.clear()
            for entry in kept:
                log.append(entry)
        return removed

    if lock_obj is not None and hasattr(lock_obj, "__enter__") and hasattr(lock_obj, "__exit__"):
        lock_cm = cast(ContextManager[Any], lock_obj)
        with lock_cm:
            return _compute_and_apply()
    try:
        return _compute_and_apply()
    except Exception:
        return 0
