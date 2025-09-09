from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

from app.settings import (
    VERIFIER_ADAPTIVE_ROUTING_ENABLED,
    VERIFIER_ADAPTIVE_HALFLIFE_S,
    VERIFIER_ADAPTIVE_MIN_SAMPLES,
    VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS,
    VERIFIER_ADAPTIVE_PENALTY_ERROR_MS,
    VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS,
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
        # (tenant, bot) -> (last_order, when_ranked)
        self._last_order: Dict[Tuple[str, str], Tuple[List[str], float]] = {}

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

    def _prune(self) -> None:
        ttl = max(60.0, float(VERIFIER_ADAPTIVE_TTL_S))
        now = self._now()

        # prune stats (keys are (tenant, bot, provider))
        stale_stats_keys = [
            k_stats for k_stats, v in self._stats.items() if (now - v.last_touch) > ttl
        ]
        for k_stats in stale_stats_keys:
            self._stats.pop(k_stats, None)

        # prune cached last order (keys are (tenant, bot))
        stale_order_keys = [
            k_tb for k_tb, (_order, ts) in self._last_order.items() if (now - ts) > ttl
        ]
        for k_tb in stale_order_keys:
            self._last_order.pop(k_tb, None)

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
        if cached is not None:
            last_order, ts = cached
            if (now - ts) < float(VERIFIER_ADAPTIVE_STICKY_S):
                return last_order[:]

        # Compute scores and rank
        base_idx = {p: i for i, p in enumerate(providers)}
        scored: List[Tuple[float, str]] = [
            (self._score(tenant, bot, p), p) for p in providers
        ]

        # If all are inf (cold start), keep default order but cache it for stickiness
        if all(math.isinf(sc) for sc, _ in scored):
            self._last_order[tb] = (providers[:], now)
            self._prune()
            return providers[:]

        ranked = sorted(scored, key=lambda t: (t[0], base_idx[t[1]]))
        out = [p for _, p in ranked]

        # Cache the computed order for the sticky window
        self._last_order[tb] = (out[:], now)
        self._prune()
        return out
