from __future__ import annotations

import time
from typing import Optional

from app import settings
from app.runtime import get_purge_coordinator, get_retention_store
from app.services.metrics import (
    purge_duration_seconds,
    purge_items_deleted_total,
    purge_runs_total,
)
from app.services.retention import RetentionPolicy


async def run_once(
    now: Optional[float] = None, per_resource_limit: int = 100
) -> int:
    if not settings.RETENTION_WORKER_ENABLED:
        return 0

    store = get_retention_store()
    coordinator = get_purge_coordinator()
    policies = await store.list_policies()
    current = now if now is not None else time.time()
    limit = max(1, min(per_resource_limit, settings.RETENTION_MAX_IDS_PER_RUN))
    deleted_total = 0
    started = time.time()

    for policy in policies:
        if not _policy_active(policy):
            continue
        try:
            ids = await coordinator.plan(
                policy.tenant, policy.resource.value, current, limit
            )
            if not ids:
                continue
            receipt = await coordinator.execute(
                policy.tenant,
                policy.resource.value,
                ids,
                dry_run=False,
                actor="scheduler",
                mode="auto",
            )
            deleted_total += int(receipt.count)
            try:
                purge_items_deleted_total.labels(policy.resource.value).inc(
                    int(receipt.count)
                )
            except Exception:
                pass
        except Exception:
            continue

    try:
        purge_runs_total.inc()
        purge_duration_seconds.observe(max(time.time() - started, 0.0))
    except Exception:
        pass
    return deleted_total


def _policy_active(policy: RetentionPolicy) -> bool:
    return bool(policy.enabled and policy.ttl_seconds > 0)


__all__ = ["run_once"]
