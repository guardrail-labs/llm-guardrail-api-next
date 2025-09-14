from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

# Register a counter on the global REGISTRY at import time so it's always visible in /metrics.
try:  # pragma: no cover
    from prometheus_client import REGISTRY as _PROM_REGISTRY, Counter as _PROM_COUNTER

    _RANK_COUNTER = _PROM_COUNTER(
        "verifier_router_rank_total",
        "Count of provider rank computations by tenant and bot.",
        ["tenant", "bot"],
        registry=_PROM_REGISTRY,
    )
except Exception:  # pragma: no cover
    _PROM_REGISTRY = None
    _RANK_COUNTER = None


def _inc_rank_metric(tenant: str, bot: str) -> None:
    """Best-effort metric increment; never raises."""
    try:
        if _RANK_COUNTER is not None:
            _RANK_COUNTER.labels(tenant=tenant, bot=bot).inc()
    except Exception:
        pass


def _parse_snapshot_max() -> int:
    """Read VERIFIER_ROUTER_SNAPSHOT_MAX; fall back to 200 if invalid or < 1."""
    raw = (os.getenv("VERIFIER_ROUTER_SNAPSHOT_MAX") or "").strip()
    try:
        v = int(raw)
        return v if v >= 1 else 200
    except Exception:
        return 200


class ProviderRouter:
    """
    Minimal router needed by tests:
      - rank(tenant, bot, providers) -> order (identity) + snapshot saved
      - get_last_order_snapshot() -> list of snapshots
      - record_success/timeout/rate_limited/error: present for integration points
    This implementation focuses on observability & snapshot behavior without changing routing.
    """

    def __init__(self) -> None:
        # List of snapshots: each {"tenant","bot","order","last_ranked_at"}
        self._snapshot_max: int = _parse_snapshot_max()
        self._order_snapshots: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Ranking
    # -------------------------------------------------------------------------
    def rank(self, tenant: str, bot: str, providers: List[str]) -> List[str]:
        """
        Return an ordering for the given providers. For Hybrid-12 scope we keep
        ordering stable (identity), record a bounded snapshot, and emit a metric.
        """
        order = list(providers)
        self._append_snapshot(tenant, bot, order)
        _inc_rank_metric(tenant, bot)
        return order

    def _append_snapshot(self, tenant: str, bot: str, order: List[str]) -> None:
        snap = {
            "tenant": tenant,
            "bot": bot,
            "order": list(order),
            "last_ranked_at": float(time.time()),
        }
        self._order_snapshots.append(snap)
        # Cap in-place; keep newest N.
        if len(self._order_snapshots) > self._snapshot_max:
            excess = len(self._order_snapshots) - self._snapshot_max
            if excess > 0:
                del self._order_snapshots[0:excess]

    # -------------------------------------------------------------------------
    # Snapshot access
    # -------------------------------------------------------------------------
    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        # Return a shallow copy to prevent external mutation.
        return list(self._order_snapshots)

    # -------------------------------------------------------------------------
    # Telemetry hooks (no-ops for now; present to satisfy integrations/tests)
    # -------------------------------------------------------------------------
    def record_success(
        self,
        tenant: str,
        bot: str,
        provider: str,
        duration_ms: int,
    ) -> None:
        # Hook for success accounting; intentionally a no-op here.
        return None

    def record_timeout(self, tenant: str, bot: str, provider: str) -> None:
        return None

    def record_rate_limited(self, tenant: str, bot: str, provider: str) -> None:
        return None

    def record_error(self, tenant: str, bot: str, provider: str) -> None:
        return None
