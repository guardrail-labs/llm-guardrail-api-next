from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------- helpers -----------------------------------------------------

def _now() -> float:
    return time.time()


def _parse_snapshot_max() -> int:
    raw = (os.getenv("VERIFIER_ROUTER_SNAPSHOT_MAX") or "").strip()
    try:
        v = int(raw)
        return v if v >= 1 else 200
    except Exception:
        return 200


def _has_decision(res: Any) -> bool:
    return isinstance(res, dict) and "decision" in res


# ---------------- simple ProviderRouter (rank + snapshots + metric) -----------

class ProviderRouter:
    """
    - rank(): identity order
    - snapshots capped by VERIFIER_ROUTER_SNAPSHOT_MAX (default 200)
    - emits verifier_router_rank_total via observability.metrics helper
    """

    def __init__(self) -> None:
        self._snapshot_max: int = _parse_snapshot_max()
        # Each snapshot: {"tenant","bot","order","last_ranked_at"}
        self._order_snapshots: List[Dict[str, Any]] = []

    def rank(self, tenant: str, bot: str, providers: Sequence[str]) -> List[str]:
        order = list(providers)
        self._append_snapshot(tenant, bot, order)

        # Soft-hook metric (no hard dep on prometheus here)
        try:
            from app.observability.metrics import inc_verifier_router_rank

            inc_verifier_router_rank(tenant, bot)
        except Exception:
            # Never break ranking due to metrics issues.
            pass

        return order

    def _append_snapshot(self, tenant: str, bot: str, order: List[str]) -> None:
        snap = {
            "tenant": tenant,
            "bot": bot,
            "order": list(order),
            "last_ranked_at": float(_now()),
        }
        self._order_snapshots.append(snap)
        if len(self._order_snapshots) > self._snapshot_max:
            excess = len(self._order_snapshots) - self._snapshot_max
            if excess > 0:
                del self._order_snapshots[0:excess]

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        return list(self._order_snapshots)

    # Telemetry hooks (no-ops; kept for compatibility)
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


# ---------------- compatibility API expected by tests -------------------------

@dataclass(frozen=True)
class ProviderSpec:
    name: str
    fn: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
    timeout_sec: float = 3.0
    max_retries: int = 0


@dataclass(frozen=True)
class RouterConfig:
    total_budget_sec: float = 2.0
    breaker_fail_threshold: int = 3
    breaker_cooldown_sec: float = 30.0


class _ProviderState:
    __slots__ = ("consecutive_failures", "open_until")

    def __init__(self) -> None:
        self.consecutive_failures: int = 0
        self.open_until: float = 0.0


class VerifierRouter:
    """
    - Uses ProviderSpec list to attempt calls within a total time budget
    - Per-provider timeout + retries (max_retries)
    - Simple circuit breaker (threshold -> open for cooldown)
    - Exposes rank/snapshot methods by delegating to ProviderRouter
    - record_* hooks are no-ops here; signatures match callers
    """

    def __init__(
        self,
        providers: Optional[Iterable[ProviderSpec]] = None,
        config: Optional[RouterConfig] = None,
    ) -> None:
        self.providers: List[ProviderSpec] = list(providers) if providers else []
        self.config: RouterConfig = config or RouterConfig()
        self._inner = ProviderRouter()
        self._state: Dict[str, _ProviderState] = {
            p.name: _ProviderState() for p in self.providers
        }

    # ---- delegate: ranking/snapshots

    def rank(self, tenant: str, bot: str, providers: Sequence[str]) -> List[str]:
        return self._inner.rank(tenant, bot, providers)

    def get_last_order_snapshot(self) -> List[Dict[str, Any]]:
        return self._inner.get_last_order_snapshot()

    # ---- telemetry hooks (no-ops)

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

    # ---- core execution

    async def route(
        self,
        payload: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        attempts_log: List[Dict[str, Any]] = []
        start = _now()
        budget = max(float(self.config.total_budget_sec), 0.0)

        def remaining_budget() -> float:
            return max(budget - (_now() - start), 0.0)

        for spec in self.providers:
            st = self._state.setdefault(spec.name, _ProviderState())
            current = _now()

            # Circuit open -> skip
            if st.open_until > current:
                attempts_log.append(
                    {
                        "provider": spec.name,
                        "ok": False,
                        "err": "circuit_open",
                        "duration_ms": 0,
                    }
                )
                continue

            tries = max(int(spec.max_retries), 0) + 1
            for attempt in range(1, tries + 1):
                if remaining_budget() <= 0:
                    attempts_log.append(
                        {
                            "provider": spec.name,
                            "attempt": attempt,
                            "ok": False,
                            "err": "budget_exhausted",
                            "duration_ms": 0,
                        }
                    )
                    break

                t0 = _now()
                try:
                    res = await asyncio.wait_for(
                        spec.fn(payload),
                        timeout=max(float(spec.timeout_sec), 0.0),
                    )
                    dur = _now() - t0
                    if _has_decision(res):
                        st.consecutive_failures = 0
                        st.open_until = 0.0
                        self.record_success("", "", spec.name, dur)
                        attempts_log.append(
                            {
                                "provider": spec.name,
                                "attempt": attempt,
                                "ok": True,
                                "duration_ms": int(dur * 1000),
                            }
                        )
                        return res, attempts_log

                    # Treat non-decision results as failures to allow retry.
                    raise RuntimeError("invalid_result")
                except asyncio.TimeoutError:
                    st.consecutive_failures += 1
                    self.record_timeout("", "", spec.name)
                    attempts_log.append(
                        {
                            "provider": spec.name,
                            "attempt": attempt,
                            "ok": False,
                            "err": "timeout",
                            "duration_ms": int((_now() - t0) * 1000),
                        }
                    )
                except Exception as e:
                    st.consecutive_failures += 1
                    self.record_error("", "", spec.name)
                    attempts_log.append(
                        {
                            "provider": spec.name,
                            "attempt": attempt,
                            "ok": False,
                            "err": str(e),
                            "duration_ms": int((_now() - t0) * 1000),
                        }
                    )

                # If threshold reached, open circuit and stop trying this provider.
                if st.consecutive_failures >= int(self.config.breaker_fail_threshold):
                    st.open_until = _now() + float(self.config.breaker_cooldown_sec)
                    break

        return None, attempts_log
