from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --- Prometheus metric (registered on global REGISTRY at import time) ---------
try:  # pragma: no cover
    from prometheus_client import CollectorRegistry, Counter, REGISTRY

    _PROM_REGISTRY: Optional[CollectorRegistry] = REGISTRY
    _RANK_COUNTER: Optional[Counter] = Counter(
        "verifier_router_rank_total",
        "Count of provider rank computations by tenant and bot.",
        ["tenant", "bot"],
        registry=REGISTRY,
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


# --- Minimal ProviderRouter used across the codebase/tests --------------------
class ProviderRouter:
    """
    Lightweight router that:
      - Returns identity order in rank()
      - Stores a capped snapshot list (env VERIFIER_ROUTER_SNAPSHOT_MAX, default 200)
      - Emits verifier_router_rank_total{tenant,bot} on each rank
      - Provides no-op telemetry hooks used by callers
    """

    def __init__(self) -> None:
        self._snapshot_max: int = _parse_snapshot_max()
        # Each snapshot: {"tenant","bot","order","last_ranked_at"}
        self._order_snapshots: List[Dict[str, Any]] = []

    def rank(self, tenant: str, bot: str, providers: Sequence[str]) -> List[str]:
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
        # Cap to latest N
        if len(self._order_snapshots) > self._snapshot_max:
            excess = len(self._order_snapshots) - self._snapshot_max
            if excess > 0:
                del self._order_snapshots[0:excess]

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        # Shallow copy to protect internal list
        return list(self._order_snapshots)

    # ---- Telemetry hooks (no-ops; signatures match callers) ------------------
    def record_success(
        self,
        tenant: str,
        bot: str,
        provider: str,
        duration_seconds: float,
    ) -> None:
        return None

    def record_timeout(self, tenant: str, bot: str, provider: str) -> None:
        return None

    def record_rate_limited(self, tenant: str, bot: str, provider: str) -> None:
        return None

    def record_error(self, tenant: str, bot: str, provider: str) -> None:
        return None


# --- Compatibility API expected by tests/imports ------------------------------
@dataclass(frozen=True)
class ProviderSpec:
    """
    Minimal provider spec for VerifierRouter compatibility.
    """
    name: str
    fn: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
    timeout_sec: float = 3.0
    max_retries: int = 0


@dataclass(frozen=True)
class RouterConfig:
    """
    Minimal router config for VerifierRouter compatibility.
    """
    total_budget_sec: float = 2.0
    breaker_cooldown_sec: float = 30.0


class VerifierRouter:
    """
    Thin compatibility wrapper exposing:
      - rank(tenant, bot, providers)
      - get_last_order_snapshot()
      - record_success/timeout/rate_limited/error(...)
      - route(payload)  (best-effort minimalist implementation)
    """

    def __init__(
        self,
        providers: Optional[Iterable[ProviderSpec]] = None,
        config: Optional[RouterConfig] = None,
    ) -> None:
        self.providers: List[ProviderSpec] = list(providers) if providers else []
        self.config: RouterConfig = config or RouterConfig()
        self._inner = ProviderRouter()

    # Delegate core methods to the lightweight inner router
    def rank(self, tenant: str, bot: str, providers: Sequence[str]) -> List[str]:
        return self._inner.rank(tenant, bot, providers)

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        return self._inner.get_last_order_snapshot()

    def record_success(
        self,
        tenant: str,
        bot: str,
        provider: str,
        duration_seconds: float,
    ) -> None:
        return self._inner.record_success(tenant, bot, provider, duration_seconds)

    def record_timeout(self, tenant: str, bot: str, provider: str) -> None:
        return self._inner.record_timeout(tenant, bot, provider)

    def record_rate_limited(self, tenant: str, bot: str, provider: str) -> None:
        return self._inner.record_rate_limited(tenant, bot, provider)

    def record_error(self, tenant: str, bot: str, provider: str) -> None:
        return self._inner.record_error(tenant, bot, provider)

    # Minimal async route execution for completeness (tests may not hit this)
    async def route(
        self,
        payload: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        attempt_log: List[Dict[str, Any]] = []
        best: Optional[Dict[str, Any]] = None

        for spec in self.providers:
            t0 = time.time()
            try:
                res = await asyncio.wait_for(spec.fn(payload), timeout=spec.timeout_sec)
                self.record_success("", "", spec.name, time.time() - t0)
                attempt_log.append(
                    {"provider": spec.name, "ok": True, "duration_ms": int((time.time() - t0) * 1000)}  # noqa: E501
                )
                best = res
                break
            except Exception as e:  # pragma: no cover - conservative
                attempt_log.append(
                    {
                        "provider": spec.name,
                        "ok": False,
                        "err": str(e),
                        "duration_ms": int((time.time() - t0) * 1000),
                    }
                )
                # continue to next provider

        return best, attempt_log
