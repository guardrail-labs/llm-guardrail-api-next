from __future__ import annotations

import os
import platform
import time
from typing import Dict, List, Optional, Tuple

from redis.asyncio import Redis

from app.services.purge_receipts import (
    PurgeReceipt,
    Signer,
    load_receipt,
    store_receipt,
)
from app.services.purge_receipts import (
    latest_receipts as load_latest_receipts,
)
from app.services.purge_targets import PurgeTarget
from app.services.retention import RetentionStore


class PurgeCoordinator:
    def __init__(
        self,
        redis: Redis,
        store: RetentionStore,
        signer: Signer,
        targets: Dict[str, PurgeTarget],
    ) -> None:
        self._redis = redis
        self._store = store
        self._signer = signer
        self._targets = targets

    async def plan(self, tenant: str, resource: str, now: float, limit: int) -> List[str]:
        if limit <= 0:
            return []
        policy = await self._store.get_policy(tenant, resource)
        if policy is None or not policy.enabled or policy.ttl_seconds <= 0:
            return []
        target = self._targets.get(resource)
        if target is None:
            return []
        cutoff = now - float(policy.ttl_seconds)
        ids = await target.list_expired(tenant, cutoff, limit)
        return ids[:limit]

    async def execute(
        self,
        tenant: str,
        resource: str,
        ids: List[str],
        *,
        dry_run: bool,
        actor: str,
        mode: str,
    ) -> PurgeReceipt:
        started = time.time()
        snapshot = list(ids)
        target = self._targets.get(resource)
        deleted = 0
        if not dry_run and target is not None and snapshot:
            deleted = await target.purge_ids(tenant, snapshot)
        completed = time.time()
        receipt = PurgeReceipt.build(
            tenant=tenant,
            resource=resource,
            count=deleted if not dry_run else 0,
            ids=snapshot,
            started_ts=started,
            completed_ts=completed,
            actor=actor,
            mode=mode if mode in {"auto", "manual"} else "manual",
            dry_run=dry_run,
            meta=self._meta(),
        )
        signature = self._signer.sign(receipt)
        await store_receipt(self._redis, receipt, signature)
        return receipt

    async def latest_receipts(self, tenant: str, limit: int) -> List[PurgeReceipt]:
        return await load_latest_receipts(self._redis, tenant, limit)

    async def get_receipt(self, receipt_id: str) -> Optional[Tuple[PurgeReceipt, Dict[str, str]]]:
        return await load_receipt(self._redis, receipt_id)

    async def verify_receipt(self, receipt_id: str) -> bool:
        stored = await self.get_receipt(receipt_id)
        if stored is None:
            return False
        receipt, signature = stored
        return self._signer.verify(receipt, signature)

    def _meta(self) -> Dict[str, str]:
        return {
            "host": platform.node() or "unknown",
            "instance": os.getenv("HOSTNAME", "unknown"),
            "version": os.getenv("APP_VERSION", "unknown"),
        }


__all__ = ["PurgeCoordinator"]
