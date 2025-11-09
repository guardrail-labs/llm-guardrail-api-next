from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# ---- Types -------------------------------------------------------------------

ProviderFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


@dataclass(frozen=True)
class ProviderSpec:
    """
    Describes a single verifier provider.
    - name: logical provider name
    - fn: async function(payload) -> dict with at least {"decision": "..."}
    - timeout_sec: max seconds allowed for a single attempt
    - max_retries: number of retries (total attempts = max_retries + 1)
    """

    name: str
    fn: ProviderFn
    timeout_sec: float = 1.0
    max_retries: int = 0


@dataclass(frozen=True)
class RouterConfig:
    """
    Router-wide settings.
    - total_budget_sec: overall wall-clock budget for route()
    - breaker_fail_threshold: consecutive failures to open the circuit
    - breaker_cooldown_sec: seconds to keep the circuit open before half-open probe
    """

    total_budget_sec: float = 2.0
    breaker_fail_threshold: int = 3
    breaker_cooldown_sec: float = 30.0


@dataclass
class _ProviderState:
    consecutive_failures: int = 0
    open_until: float = 0.0  # epoch seconds; > now means OPEN


# ---- Router ------------------------------------------------------------------


class VerifierRouter:
    """
    Minimal, test-friendly provider router with:
      * overall latency budget per route()
      * per-provider retries
      * simple circuit breaker (open / half-open / closed)
      * snapshot capture (capped by VERIFIER_ROUTER_SNAPSHOT_MAX env)
      * rank metric emission (verifier_router_rank_total)
    """

    def __init__(
        self,
        providers: Iterable[ProviderSpec] | None = None,
        config: Optional[RouterConfig] = None,
    ) -> None:
        self.providers: List[ProviderSpec] = list(providers or [])
        self.config: RouterConfig = config or RouterConfig()

        # Per-provider breaker/health state
        self._state: Dict[str, _ProviderState] = {p.name: _ProviderState() for p in self.providers}

        # Snapshot ring buffer
        self._snapshot_max: int = self._parse_int_env("VERIFIER_ROUTER_SNAPSHOT_MAX", 200)
        self._order_snapshots: List[Dict[str, Any]] = []

    # ---- Utilities ------------------------------------------------------------

    @staticmethod
    def _parse_int_env(name: str, default: int) -> int:
        raw = (os.getenv(name) or "").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            return val if val > 0 else default
        except Exception:
            return default

    @staticmethod
    def _remaining_budget(start_t: float, total_budget_sec: float) -> float:
        """Seconds remaining in the overall budget (infinite if <=0)."""
        if total_budget_sec <= 0:
            return float("inf")
        spent = max(time.perf_counter() - start_t, 0.0)
        return max(total_budget_sec - spent, 0.0)

    def _is_open(self, name: str, now: float) -> bool:
        st = self._state.setdefault(name, _ProviderState())
        return st.open_until > now

    def _open_circuit(self, name: str, cooldown_sec: float) -> None:
        st = self._state.setdefault(name, _ProviderState())
        st.open_until = time.perf_counter() + max(cooldown_sec, 0.0)

    def _close_circuit(self, name: str) -> None:
        st = self._state.setdefault(name, _ProviderState())
        st.open_until = 0.0
        st.consecutive_failures = 0

    # ---- Public API used by other modules/tests ------------------------------

    def rank(self, tenant: str, bot: str, base_names: List[str]) -> List[str]:
        """
        Return the provider order for a (tenant, bot). For now we preserve
        the given order, but we:
          * capture a capped snapshot with timestamp, tenant, bot, order
          * emit a Prometheus counter for visibility
        """
        snapshot = {
            "tenant": tenant,
            "bot": bot,
            "order": list(base_names),
            "last_ranked_at": float(time.time()),
        }
        self._order_snapshots.append(snapshot)
        if len(self._order_snapshots) > self._snapshot_max:
            # keep latest N
            self._order_snapshots = self._order_snapshots[-self._snapshot_max :]

        # Emit counter on the same registry the /metrics endpoint exports.
        try:
            from app.observability.metrics import inc_verifier_router_rank

            inc_verifier_router_rank(tenant, bot)
        except Exception:
            # Never break ranking if metrics are unavailable.
            pass

        return list(base_names)

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        """Return the in-memory snapshot list (newest last)."""
        return list(self._order_snapshots)

    # External signals from callers (integration hooks)
    def record_timeout(self, tenant: str, bot: str, provider: str) -> None:
        self._bump_failure(provider)

    def record_rate_limited(self, tenant: str, bot: str, provider: str) -> None:
        self._bump_failure(provider)

    def record_error(self, tenant: str, bot: str, provider: str) -> None:
        self._bump_failure(provider)

    def record_success(
        self,
        tenant: str,
        bot: str,
        provider: str,
        duration_sec: float,  # keep float to match existing callers
    ) -> None:
        self._close_circuit(provider)

    # ---- Internal bookkeeping -------------------------------------------------

    def _bump_failure(self, name: str) -> None:
        st = self._state.setdefault(name, _ProviderState())
        st.consecutive_failures += 1
        if st.consecutive_failures >= self.config.breaker_fail_threshold:
            self._open_circuit(name, self.config.breaker_cooldown_sec)

    # ---- Routing core ---------------------------------------------------------

    async def route(
        self, payload: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Try providers in order with retries, honoring the overall time budget.
        Returns (best_result_or_none, attempt_log).
        attempt_log entries: {"provider","attempt","ok","duration_ms",...}
        """
        attempt_log: List[Dict[str, Any]] = []
        start_all = time.perf_counter

        for spec in self.providers:
            now = time.perf_counter()
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
                continue

            attempts = max(int(spec.max_retries) + 1, 1)
            for i in range(1, attempts + 1):
                remaining = self._remaining_budget(start_all(), self.config.total_budget_sec)
                if remaining <= 0.0:
                    attempt_log.append(
                        {
                            "provider": spec.name,
                            "attempt": i,
                            "ok": False,
                            "err": "budget_exhausted",
                            "duration_ms": 0,
                        }
                    )
                    # Out of budget; move on to next provider.
                    break

                t0 = time.perf_counter()
                try:
                    # Cap per-attempt timeout to remaining router budget.
                    per_attempt_timeout = min(max(float(spec.timeout_sec), 0.0), remaining)
                    if per_attempt_timeout <= 0.0:
                        raise asyncio.TimeoutError()

                    res = await asyncio.wait_for(
                        spec.fn(payload),
                        timeout=per_attempt_timeout,
                    )

                    if not isinstance(res, dict) or "decision" not in res:
                        # Treat shape issues as a failed attempt (triggers retry).
                        raise ValueError("bad_response")

                    # Success
                    self._close_circuit(spec.name)
                    attempt_log.append(
                        {
                            "provider": spec.name,
                            "attempt": i,
                            "ok": True,
                            "duration_ms": int((time.perf_counter() - t0) * 1000),
                        }
                    )
                    return res, attempt_log

                except asyncio.TimeoutError:
                    # Timeout -> failure + possible breaker open
                    self._bump_failure(spec.name)
                    attempt_log.append(
                        {
                            "provider": spec.name,
                            "attempt": i,
                            "ok": False,
                            "err": "timeout",
                            "duration_ms": int((time.perf_counter() - t0) * 1000),
                        }
                    )
                    continue
                except Exception as e:
                    # Generic failure -> failure + possible breaker open
                    self._bump_failure(spec.name)
                    attempt_log.append(
                        {
                            "provider": spec.name,
                            "attempt": i,
                            "ok": False,
                            "err": type(e).__name__,
                            "duration_ms": int((time.perf_counter() - t0) * 1000),
                        }
                    )
                    continue

            # move to next provider
            continue

        # No provider produced a result.
        return None, attempt_log


# Re-export alias for legacy imports in tests/callers
ProviderRouter = VerifierRouter

__all__ = [
    "ProviderSpec",
    "RouterConfig",
    "VerifierRouter",
    "ProviderRouter",
]
