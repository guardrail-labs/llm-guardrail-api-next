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

# ----------------------------- Public Interfaces -----------------------------

# Any async callable returning a mapping with a "decision" key is treated
# as a successful verifier result.
ProviderFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


@dataclass
class ProviderSpec:
    name: str
    fn: ProviderFn
    timeout_sec: float = 3.0
    max_retries: int = 1  # attempts = max_retries + 1


@dataclass
class RouterConfig:
    # Overall routing budget across all providers (seconds). 0 → unlimited.
    total_budget_sec: float = 5.0
    # Circuit breaker: open after N consecutive failures; cool down for X sec.
    breaker_fail_threshold: int = 3
    breaker_cooldown_sec: int = 30
    # Half-open allows a single probation call when cooldown elapses.
    enable_half_open: bool = True


@dataclass
class ProviderState:
    failures: int = 0
    open_until: float = 0.0
    half_open: bool = False


# ------------------------------- Utilities -----------------------------------

def _read_int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    """
    Parse an int env var safely. On missing/invalid/empty value, fall back
    to default. If `minimum` is set and the parsed value is below it, fall
    back to default.
    """
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
            # Cooldown elapsed → allow one probation request.
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

    def _emit_metric(self, kind: str, labels: Dict[str, str]) -> None:
        """
        Soft hook: try to emit internal metrics if available.
        Optional to avoid hard deps in this module.
        """
        try:
            from app.observability.metrics import inc_counter
            inc_counter(f"verifier_router_{kind}_total", labels)
        except Exception:
            pass

    async def route(
        self,
        payload: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Returns (best_result_or_none, attempt_log).
        attempt_log is a list of {provider, attempt, ok, err?, duration_ms}.
        """
        attempt_log: List[Dict[str, Any]] = []
        budget = self.config.total_budget_sec
        start_all = time.time()
        exhausted = False

        def remaining_budget() -> float:
            if budget <= 0:
                return float("inf")
            return max(0.0, budget - (time.time() - start_all))

        for spec in self.providers:
            # Check budget before attempting this provider.
            if budget > 0 and remaining_budget() <= 0.0:
                exhausted = True
                break

            now = time.time()

            # Circuit breaker: skip if still open.
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

            # Half-open probe allowed?
            half_open_probe = self._should_probe_half_open(spec.name, now)

            attempts = spec.max_retries + 1
            for i in range(1, attempts + 1):
                # Enforce budget inside retry loop.
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

                # Optionally cap this attempt’s timeout to remaining budget.
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

                # Record failure and decide next step.
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

                # If half-open probing, any failure re-opens immediately; stop.
                if half_open_probe:
                    st = self._state[spec.name]
                    st.open_until = time.time() + self.config.breaker_cooldown_sec
                    st.half_open = False
                    break

            if exhausted:
                break

        # Budget exhausted or all providers failed
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
        # List of snapshots: {"tenant","bot","order","last_ranked_at","ts_ms"}
        self._order_snapshots: List[Dict[str, Any]] = []
        # Simple counters by (tenant, bot, provider)
        self._stats: Dict[Tuple[str, str, str], Dict[str, int]] = {}
        # Safe parse with default and minimum bound.
        self._snapshot_max = _read_int_env(
            "VERIFIER_ROUTER_SNAPSHOT_MAX",
            default=200,
            minimum=1,
        )

    # --- rank metric emission with robust fallback ---

    def _emit_rank_metric(self, tenant: str, bot: str) -> None:
        # Preferred path: use app helper registered on the same REGISTRY.
        try:
            from app.observability.metrics import inc_verifier_router_rank

            inc_verifier_router_rank(tenant, bot)
            return
        except Exception:
            pass

        # Fallback: register/increment directly on REGISTRY without crashing.
        try:
            from prometheus_client import REGISTRY, Counter

            # Try to reuse an existing collector if already registered.
            counter = None
            try:
                counter = getattr(REGISTRY, "_names_to_collectors", {}).get(
                    "verifier_router_rank_total"
                )
            except Exception:
                counter = None

            if counter is None:
                try:
                    counter = Counter(
                        "verifier_router_rank_total",
                        (
                            "Count of provider rank computations by "
                            "tenant and bot."
                        ),
                        ["tenant", "bot"],
                        registry=REGISTRY,
                    )
                except Exception:
                    counter = getattr(REGISTRY, "_names_to_collectors", {}).get(
                        "verifier_router_rank_total"
                    )

            if counter is not None:
                counter.labels(tenant=tenant, bot=bot).inc()
        except Exception:
            # Never let metrics failures affect routing.
            pass

    # --- public API ---

    def rank(self, tenant: str, bot: str, providers: List[str]) -> List[str]:
        # Deterministic pass-through: preserve input order.
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
        # Cap memory: keep only the most recent N snapshots.
        if len(self._order_snapshots) > self._snapshot_max:
            drop = len(self._order_snapshots) - self._snapshot_max
            if drop > 0:
                self._order_snapshots = self._order_snapshots[drop:]

        self._emit_rank_metric(tenant, bot)
        return ordered

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        # Return a shallow copy of all snapshots as a list of dicts.
        return list(self._order_snapshots)

    # --- outcome recording hooks (no-op counters, for compatibility) ---

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
        # Store duration as an int; tolerate float input from perf counters.
        k = (tenant, bot, provider)
        bucket = self._stats.setdefault(k, {})
        bucket["success"] = bucket.get("success", 0) + 1
        bucket["last_duration_ms"] = int(duration_ms)
