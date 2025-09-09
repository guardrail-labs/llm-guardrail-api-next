from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

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
    # EWMA success prob in [0,1]
    p_ok: float = 0.8
    # total observations
    n: int = 0
    # last reorder timestamp
    last_ranked_at: float = 0.0
    # last touch for TTL
    last_touch: float = 0.0


class ProviderRouter:
    """Per-tenant/bot adaptive provider ordering using EWMA scoring."""

    def __init__(self) -> None:
        self._stats: Dict[Tuple[str, str, str], _Stat] = {}

    def _key(self, tenant: str, bot: str, prov: str) -> Tuple[str, str, str]:
        return (tenant or "default", bot or "default", prov or "unknown")

    def _alpha(self, dt: float) -> float:
        hl = max(1.0, float(VERIFIER_ADAPTIVE_HALFLIFE_S))
        return 1.0 - math.exp(-math.log(2.0) * max(0.0, dt) / hl)

    def _now(self) -> float:
        return time.time()

    def _touch(self, k: Tuple[str, str, str]) -> _Stat:
        s = self._stats.get(k)
        if not s:
            s = _Stat()
            self._stats[k] = s
        s.last_touch = self._now()
        return s

    def _prune(self) -> None:
        ttl = max(60.0, float(VERIFIER_ADAPTIVE_TTL_S))
        now = self._now()
        stale = [k for k, v in self._stats.items() if (now - v.last_touch) > ttl]
        for k in stale:
            self._stats.pop(k, None)

    def record_success(self, tenant: str, bot: str, prov: str, latency_s: float) -> None:
        k = self._key(tenant, bot, prov)
        s = self._touch(k)
        dt = 1.0
        a = self._alpha(dt)
        lat_ms = max(1.0, float(latency_s) * 1000.0)
        s.lat_ms = (1 - a) * s.lat_ms + a * lat_ms
        s.p_ok = (1 - a) * s.p_ok + a * 1.0
        s.n += 1
        self._prune()

    def record_timeout(self, tenant: str, bot: str, prov: str) -> None:
        k = self._key(tenant, bot, prov)
        s = self._touch(k)
        dt = 1.0
        a = self._alpha(dt)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS, s.lat_ms
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.0
        s.n += 1
        self._prune()

    def record_error(self, tenant: str, bot: str, prov: str) -> None:
        k = self._key(tenant, bot, prov)
        s = self._touch(k)
        dt = 1.0
        a = self._alpha(dt)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            VERIFIER_ADAPTIVE_PENALTY_ERROR_MS, s.lat_ms * 0.9
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.2
        s.n += 1
        self._prune()

    def record_rate_limited(self, tenant: str, bot: str, prov: str) -> None:
        k = self._key(tenant, bot, prov)
        s = self._touch(k)
        dt = 1.0
        a = self._alpha(dt)
        s.lat_ms = (1 - a) * s.lat_ms + a * max(
            VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS, s.lat_ms
        )
        s.p_ok = (1 - a) * s.p_ok + a * 0.1
        s.n += 1
        self._prune()

    def rank(self, tenant: str, bot: str, providers: List[str]) -> List[str]:
        if not VERIFIER_ADAPTIVE_ROUTING_ENABLED:
            return providers[:]

        now = self._now()
        scored: List[Tuple[float, str]] = []
        for p in providers:
            s = self._stats.get(self._key(tenant, bot, p))
            if not s or s.n < int(VERIFIER_ADAPTIVE_MIN_SAMPLES):
                scored.append((float("inf"), p))
            else:
                p_ok = max(0.05, min(1.0, s.p_ok))
                score = s.lat_ms / p_ok
                scored.append((score, p))

        if all(math.isinf(sc) for sc, _ in scored):
            return providers[:]

        base_idx = {p: i for i, p in enumerate(providers)}
        ranked = sorted(scored, key=lambda t: (t[0], base_idx[t[1]]))
        out = [p for _, p in ranked]

        top = out[0]
        k = self._key(tenant, bot, top)
        s = self._stats.get(k)
        if s and (now - s.last_ranked_at) < float(VERIFIER_ADAPTIVE_STICKY_S):
            return providers[:]

        if s:
            s.last_ranked_at = now
        return out

