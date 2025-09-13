from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from app.settings import (
    VERIFIER_ADAPTIVE_HALFLIFE_S,
    VERIFIER_ADAPTIVE_MIN_SAMPLES,
    VERIFIER_ADAPTIVE_PENALTY_ERROR_MS,
    VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS,
    VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS,
    VERIFIER_ADAPTIVE_ROUTING_ENABLED,
    VERIFIER_ADAPTIVE_STICKY_S,
    VERIFIER_ADAPTIVE_TTL_S,
)


@dataclass
class _Stat:
    # EWMA latency in ms
    lat_ms: float = 300.0
    # EWMA success prob in [0, 1]
    p_ok: float = 0.8
    # observations
    n: int = 0
    # last touch for TTL pruning
    last_touch: float = 0.0


class ProviderRouter:
    """
    Per-(tenant, bot) adaptive ordering using simple EWMA scoring.

    Score (lower is better):
        score = lat_ms / max(p_ok, 0.05)

    We apply implicit "penalties" by nudging the EWMA via the record_* events.

    Sticky window semantic:
      - During a short sticky window, continue returning the *last ranked order*
        instead of recomputing and then falling back to the static provider list.
    """

    def __init__(self) -> None:
        # (tenant, bot, provider) -> stats
        self._stats: Dict[Tuple[str, str, str], _Stat] = {}
        # (tenant, bot) -> {"order": [...], "last_ranked_at": ts}
        self._last_order: dict[tuple[str, str], dict[str, Any]] = {}

    # ---- internals -----------------------------------------------------------

    def _tb(self, tenant: str, bot: str) -> Tuple[str, str]:
        return (tenant or "default", bot or "default")

    def _key(self, tenant: str, bot: str, prov: str) -> Tuple[str, str, str]:
        return (tenant or "default", bot or "default", prov or "unknown")

    def _now(self) -> float:
        return time.time()

    def _alpha(self, dt: float) -> float:
        # EWMA decay: alpha = 1 - exp(-ln(2) * dt / half_life)
        hl = max(1.0, float(VERIFIER_ADAPTIVE_HALFLIFE_S))
        return 1.0 - math.exp(-math.log(2.0) * max(0.0, dt) / hl)

    def _touch(self, k_stats: Tuple[str, str, str]) -> _Stat:
        s = self._stats.get(k_stats)
        if not s:
            s = _Stat()
            self._stats[k_stats] = s
        s.last_touch = self._now()
        return s

    def _prune(self, now: float | None = None) -> None:
        """Prune stale stats and sticky-cache entries."""
        ttl = max(60.0, float(VERIFIER_ADAPTIVE_TTL_S))
        now = self._now() if now is None else now

        # prune stats (keys are (tenant, bot, provider))
        stale_stats_keys = [
            k_stats for k_stats, v in self._stats.items() if (now - v.last_touch) > ttl
        ]
        for k_stats in stale_stats_keys:
            self._stats.pop(k_stats, None)

        # prune cached last order using sticky-horizon (10x sticky window)
        try:
            horizon = float(VERIFIER_ADAPTIVE_STICKY_S) * 10.0
        except Exception:
            horizon = 600.0
        dead = []
        for k, payload in self._last_order.items():
            ts = float(payload.get("last_ranked_at") or 0.0)
            if now - ts > horizon:
                dead.append(k)
        for k in dead:
            self._last_order.pop(k, None)

    def get_last_order_snapshot(self) -> list[dict[str, object]]:
        """Return a snapshot of cached last orders for ops inspection."""
        snap: list[dict[str, object]] = []
        for (tenant, bot), payload in self._last_order.items():
            order_val = payload.get("order")
            order_list = list(order_val) if isinstance(order_val, list) else []
            snap.append(
                {
                    "tenant": tenant,
                    "bot": bot,
                    "order": order_list,
                    "last_ranked_at": float(payload.get("last_ranked_at") or 0.0),
                }
            )
        return snap

    # ---- event ingestion -----------------------------------------------------

    def record_success(self, tenant: str, bot: str, prov: str, latency_s: float) -> None:
        k_stats = self._key(tenant, bot, prov)
        s = self._touch(k_stats)
        a = self._alpha(1.0)
        lat_ms = max(1.0, float(latency_s) * 1000.0)
        s.lat_ms = (1 - a) * s.lat_ms + a * lat_ms
        s.p_ok = (1 - a) * s.p_ok + a * 1.0
        s.n += 1
        self._prune()

    def record_timeout(self, tenant: str, bot: str, prov: str) -> None:
        k_stats = self._key(tenant, bot, prov)
        s = self._touch(k_stats)
        a = self._alpha(1.0)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            float(VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS), s.lat_ms
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.0
        s.n += 1
        self._prune()

    def record_error(self, tenant: str, bot: str, prov: str) -> None:
        k_stats = self._key(tenant, bot, prov)
        s = self._touch(k_stats)
        a = self._alpha(1.0)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            float(VERIFIER_ADAPTIVE_PENALTY_ERROR_MS), s.lat_ms * 0.9
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.2
        s.n += 1
        self._prune()

    def record_rate_limited(self, tenant: str, bot: str, prov: str) -> None:
        k_stats = self._key(tenant, bot, prov)
        s = self._touch(k_stats)
        a = self._alpha(1.0)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            float(VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS), s.lat_ms
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.1
        s.n += 1
        self._prune()

    # ---- ranking -------------------------------------------------------------

    def _score(self, tenant: str, bot: str, provider: str) -> float:
        s = self._stats.get(self._key(tenant, bot, provider))
        if not s or s.n < int(VERIFIER_ADAPTIVE_MIN_SAMPLES):
            return float("inf")
        p_ok = max(0.05, min(1.0, s.p_ok))
        return s.lat_ms / p_ok

    def rank(self, tenant: str, bot: str, providers: List[str]) -> List[str]:
        """
        Return provider order for this (tenant, bot). If adaptive routing is
        disabled or no samples exist, return the input order unchanged.

        Sticky behavior:
          - If within sticky window for this (tenant, bot), return the last
            ranked order we produced previously (not the static default).
        """
        if not VERIFIER_ADAPTIVE_ROUTING_ENABLED:
            return providers[:]

        now = self._now()
        tb = self._tb(tenant, bot)

        # Sticky: if we have a recent order, keep using it
        cached = self._last_order.get(tb)
        if cached:
            ts = float(cached.get("last_ranked_at") or 0.0)
            if (now - ts) < float(VERIFIER_ADAPTIVE_STICKY_S):
                order_val = cached.get("order")
                if isinstance(order_val, list):
                    return list(order_val)
                return providers[:]

        # Compute scores and rank
        base_idx = {p: i for i, p in enumerate(providers)}
        scored: List[Tuple[float, str]] = [
            (self._score(tenant, bot, p), p) for p in providers
        ]

        # If all are inf (cold start), keep default order but cache it for stickiness
        if all(math.isinf(sc) for sc, _ in scored):
            self._last_order[tb] = {"order": providers[:], "last_ranked_at": now}
            self._prune(now)
            return providers[:]

        ranked = sorted(scored, key=lambda t: (t[0], base_idx[t[1]]))
        out = [p for _, p in ranked]

        # Cache the computed order for the sticky window
        self._last_order[tb] = {"order": out[:], "last_ranked_at": now}
        self._prune(now)
        return out


# ---------------------------------------------------------------------------
# Reliability-focused Verifier Router

# Minimal provider interface: any async callable returning a mapping with a
# "decision" key is considered a successful verifier result.
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


class VerifierRouter:
    """
    Tries providers in order with retries, timeouts, and a circuit breaker.
    A "success" is any response mapping that contains a 'decision' key.
    """

    def __init__(self, providers: Iterable[ProviderSpec], config: Optional[RouterConfig] = None) -> None:
        self.providers: List[ProviderSpec] = list(providers)
        self.config = config or RouterConfig()
        self._state: Dict[str, ProviderState] = {p.name: ProviderState() for p in self.providers}

    async def _call_with_timeout(self, spec: ProviderSpec, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await asyncio.wait_for(spec.fn(payload), timeout=spec.timeout_sec)

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
        We keep it optional to avoid hard deps in this standalone PR.
        """
        try:
            # Example: app.observability.metrics.inc_verifier(kind, labels)
            from app.observability.metrics import inc_counter  # type: ignore
            inc_counter(f"verifier_router_{kind}_total", labels)
        except Exception:
            pass

    async def route(self, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Returns (best_result_or_none, attempt_log).
        attempt_log is a list of {provider, attempt, ok, err?, duration_ms}.
        """
        attempt_log: List[Dict[str, Any]] = []
        budget = self.config.total_budget_sec
        start_all = time.time()

        for spec in self.providers:
            now = time.time()
            if budget > 0 and (now - start_all) >= budget:
                break

            st = self._state[spec.name]

            # Circuit breaker: skip if still open.
            if self._is_open(spec.name, now):
                attempt_log.append(
                    {"provider": spec.name, "attempt": 0, "ok": False, "err": "circuit_open", "duration_ms": 0}
                )
                self._emit_metric("skip_open", {"provider": spec.name})
                continue

            # Half-open probe allowed?
            half_open_probe = self._should_probe_half_open(spec.name, now)

            attempts = spec.max_retries + 1
            for i in range(1, attempts + 1):
                t0 = time.time()
                ok = False
                err_s: Optional[str] = None
                try:
                    res = await self._call_with_timeout(spec, payload)
                    ok = isinstance(res, dict) and "decision" in res
                    if ok:
                        self._record_success(spec.name)
                        self._emit_metric("success", {"provider": spec.name})
                        attempt_log.append(
                            {"provider": spec.name, "attempt": i, "ok": True, "duration_ms": int((time.time()-t0)*1000)}
                        )
                        return res, attempt_log
                    else:
                        err_s = "bad_response"
                        raise RuntimeError("Verifier returned invalid response")
                except asyncio.TimeoutError:
                    err_s = "timeout"
                except Exception as e:  # provider error
                    err_s = getattr(e, "code", None) or type(e).__name__

                # record failure and decide next step
                self._record_failure(spec.name)
                self._emit_metric("failure", {"provider": spec.name, "reason": err_s})
                attempt_log.append(
                    {"provider": spec.name, "attempt": i, "ok": False, "err": err_s,
                     "duration_ms": int((time.time()-t0)*1000)}
                )

                # If we were half-open probing, any failure re-opens immediately; stop trying this provider.
                if half_open_probe:
                    st.open_until = time.time() + self.config.breaker_cooldown_sec
                    st.half_open = False
                    break

            # exhausted retries for this provider → try next provider
            continue

        # budget exhausted or all providers failed
        self._emit_metric("exhausted", {})
        return None, attempt_log
