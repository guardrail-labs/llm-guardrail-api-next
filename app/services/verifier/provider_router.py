from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "ProviderSpec",
    "RouterConfig",
    "ProviderState",
    "VerifierRouter",
    "ProviderRouter",
]

# -----------------------------------------------------------------------------
# Metrics: define rank counter once, on the same REGISTRY that /metrics exports
# -----------------------------------------------------------------------------
try:
    from prometheus_client import REGISTRY as _PROM_REGISTRY
    from prometheus_client import Counter as _PromCounter

    _RANK_COUNTER = _PromCounter(
        "verifier_router_rank_total",
        "Count of provider rank computations by tenant and bot.",
        ["tenant", "bot"],
        registry=_PROM_REGISTRY,
    )
except Exception:  # pragma: no cover
    _RANK_COUNTER = None  # type: ignore[assignment]


# ----------------------------- Public Interfaces -----------------------------

ProviderFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


@dataclass
class ProviderSpec:
    name: str
    fn: ProviderFn
    timeout_sec: float = 3.0
    max_retries: int = 1  # attempts = max_retries + 1


@dataclass
class RouterConfig:
    total_budget_sec: float = 5.0
    breaker_fail_threshold: int = 3
    breaker_cooldown_sec: int = 30
    enable_half_open: bool = True


@dataclass
class ProviderState:
    failures: int = 0
    open_until: float = 0.0
    half_open: bool = False


# ------------------------------- Utilities -----------------------------------

def _read_int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        val = int(raw) if raw else default
    except Exception:
        val = default
    if minimum is not None and val < minimum:
        return default
    return val


# ------------------------------- Router Core ---------------------------------

class VerifierRouter:
    """
    Tries providers in order with retries, timeouts, and a circuit breaker.
    A "success" is any response mapping that contains a 'decision' key.
    """

    def __init__(
        self,
        providers: Iterable[ProviderSpec],
        config: Optional[RouterConfig] = None,
    ) -> None:
        self.providers: List[ProviderSpec] = list(providers)
        self.config = config or RouterConfig()
        self._state: Dict[str, ProviderState] = {
            p.name: ProviderState() for p in self.providers
        }

    async def _call_with_timeout(
        self,
        spec: ProviderSpec,
        payload: Dict[str, Any],
        *,
        timeout_override: Optional[float] = None,
    ) -> Dict[str, Any]:
        timeout = timeout_override if timeout_override is not None else spec.timeout_sec
        return await asyncio.wait_for(spec.fn(payload), timeout=timeout)

    def _is_open(self, name: str, now: float) -> bool:
        st = self._state[name]
        if st.open_until <= now:
            return False
        return True

    def _should_probe_half_open(self, name: str, now: float) -> bool:
        st = self._state[name]
        if not self.config.enable_half_open:
            return False
        if st.open_until <= now and st.failures >= self.config.breaker_fail_threshold:
            st.half_open = True
            return True
        return False

    def _record_success(self, name: str) -> None:
        st = self._state[name]
        st.failures = 0
        st.open_until = 0.0
        st.half_open = False

    def _record_failure(self, name: str) -> None:
        st = self._state[name]
        st.failures += 1
        if st.failures >= self.config.breaker_fail_threshold:
            st.open_until = time.time() + self.config.breaker_cooldown_sec
            st.half_open = False

    def _emit_metric(self, _kind: str, _labels: Dict[str, str]) -> None:
        # Soft hook (no-op). Kept for future use.
        return None

    async def route(
        self,
        payload: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        attempt_log: List[Dict[str, Any]] = []
        budget = self.config.total_budget_sec
        start_all = time.time()
        exhausted = False

        def remaining_budget() -> float:
            if budget <= 0:
                return float("inf")
            return max(0.0, budget - (time.time() - start_all))

        for spec in self.providers:
            if budget > 0 and remaining_budget() <= 0.0:
                exhausted = True
                break

            now = time.time()

            if self._is_open(spec.name, now):
                attempt_log.append(
                    {
                        "provider": spec.name,
                        "attempt": 0,
                        "ok": False,
                        "err": "circuit_open",
                        "duration_ms": 0,
                    }
                )
                self._emit_metric("skip_open", {"provider": spec.name})
                continue

            half_open_probe = self._should_probe_half_open(spec.name, now)

            attempts = spec.max_retries + 1
            for i in range(1, attempts + 1):
                rem = remaining_budget()
                if budget > 0 and rem <= 0.0:
                    exhausted = True
                    attempt_log.append(
                        {
                            "provider": spec.name,
                            "attempt": i,
                            "ok": False,
                            "err": "budget_exhausted",
                            "duration_ms": 0,
                        }
                    )
                    break

                timeout_override = None
                if budget > 0 and rem < float("inf"):
                    timeout_override = min(spec.timeout_sec, rem)

                t0 = time.time()
                err_s: Optional[str] = None
                try:
                    res = await self._call_with_timeout(
                        spec,
                        payload,
                        timeout_override=timeout_override,
                    )
                    ok = isinstance(res, dict) and "decision" in res
                    if ok:
                        self._record_success(spec.name)
                        self._emit_metric("success", {"provider": spec.name})
                        duration_ms = int((time.time() - t0) * 1000)
                        attempt_log.append(
                            {
                                "provider": spec.name,
                                "attempt": i,
                                "ok": True,
                                "duration_ms": duration_ms,
                            }
                        )
                        return res, attempt_log
                    err_s = "bad_response"
                    raise RuntimeError("Verifier returned invalid response")
                except asyncio.TimeoutError:
                    err_s = "timeout"
                except Exception as e:
                    err_s = getattr(e, "code", None) or type(e).__name__

                self._record_failure(spec.name)
                self._emit_metric("failure", {"provider": spec.name, "reason": err_s})
                duration_ms = int((time.time() - t0) * 1000)
                attempt_log.append(
                    {
                        "provider": spec.name,
                        "attempt": i,
                        "ok": False,
                        "err": err_s,
                        "duration_ms": duration_ms,
                    }
                )

                if half_open_probe:
                    st = self._state[spec.name]
                    st.open_until = time.time() + self.config.breaker_cooldown_sec
                    st.half_open = False
                    break

            if exhausted:
                break

        self._emit_metric("exhausted", {})
        return None, attempt_log


# ---------------------------------------------------------------------------
# Legacy, test-facing compatibility shim
# ---------------------------------------------------------------------------

class ProviderRouter:
    """
    Back-compat façade expected by older imports/tests.

    Surface:
      - rank(tenant, bot, providers) -> ordered list (deterministic)
      - get_last_order_snapshot() -> List[Dict[str, Any]]
      - record_timeout / record_rate_limited / record_error / record_success
      - capped snapshot list, rank metric emission
    """

    def __init__(self) -> None:
        self._order_snapshots: List[Dict[str, Any]] = []
        self._stats: Dict[Tuple[str, str, str], Dict[str, int]] = {}
        self._snapshot_max = _read_int_env(
            "VERIFIER_ROUTER_SNAPSHOT_MAX",
            default=200,
            minimum=1,
        )

    def _emit_rank_metric(self, tenant: str, bot: str) -> None:
        """
        First, eagerly import the app-level helper so the counter is
        registered on the same REGISTRY that /metrics scrapes. If that
        import fails for any reason, fall back to the module-local counter.
        """
        try:
            from app.observability.metrics import inc_verifier_router_rank

            inc_verifier_router_rank(tenant, bot)
            return
        except Exception:
            pass

        if _RANK_COUNTER is not None:
            try:
                _RANK_COUNTER.labels(tenant=tenant, bot=bot).inc()
            except Exception:
                pass

    def rank(self, tenant: str, bot: str, providers: List[str]) -> List[str]:
        ordered = list(providers)
        now = time.time()
        self._order_snapshots.append(
            {
                "tenant": tenant,
                "bot": bot,
                "order": ordered,
                "last_ranked_at": float(now),
                "ts_ms": int(now * 1000),
            }
        )
        if len(self._order_snapshots) > self._snapshot_max:
            drop = len(self._order_snapshots) - self._snapshot_max
            if drop > 0:
                self._order_snapshots = self._order_snapshots[drop:]

        self._emit_rank_metric(tenant, bot)
        return ordered

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        return list(self._order_snapshots)

    # --- outcome recording hooks (compat no-ops with counters kept in memory) ---

    def _bump(self, tenant: str, bot: str, provider: str, key: str) -> None:
        k = (tenant, bot, provider)
        bucket = self._stats.setdefault(k, {})
        bucket[key] = bucket.get(key, 0) + 1

    def record_timeout(self, tenant: str, bot: str, provider: str) -> None:
        self._bump(tenant, bot, provider, "timeout")

    def record_rate_limited(self, tenant: str, bot: str, provider: str) -> None:
        self._bump(tenant, bot, provider, "rate_limited")

    def record_error(self, tenant: str, bot: str, provider: str) -> None:
        self._bump(tenant, bot, provider, "error")

    def record_success(
        self,
        tenant: str,
        bot: str,
        provider: str,
        duration_ms: float | int,
    ) -> None:
        k = (tenant, bot, provider)
        bucket = self._stats.setdefault(k, {})
        bucket["success"] = bucket.get("success", 0) + 1
        bucket["last_duration_ms"] = int(duration_ms)
