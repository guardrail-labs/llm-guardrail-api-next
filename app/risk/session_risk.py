from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# Simple in-memory risk store with TTL buckets.
# Keyed by (tenant, bot, session_id). session_id is best-effort from headers.
_DEFAULT_TTL_SECS = 15 * 60  # 15 minutes
_MAX_ENTRIES = 50_000        # guard memory in hot tenants

@dataclass
class RiskEntry:
    score: float
    last: float
    ttl: float

class SessionRiskStore:
    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str, str], RiskEntry] = {}

    def _now(self) -> float:
        return time.time()

    def _gc(self) -> None:
        now = self._now()
        if len(self._store) > _MAX_ENTRIES:
            # Fast GC by dropping expired first
            keys = [k for k, v in self._store.items() if (now - v.last) > v.ttl]
            for k in keys:
                self._store.pop(k, None)
            # If still huge, drop oldest 5%
            if len(self._store) > _MAX_ENTRIES:
                items = sorted(self._store.items(), key=lambda kv: kv[1].last)
                cut = max(1, len(items) // 20)
                for k, _ in items[:cut]:
                    self._store.pop(k, None)

    def bump(
        self,
        tenant: str,
        bot: str,
        session_id: str,
        delta: float,
        ttl_seconds: Optional[float] = None,
    ) -> float:
        self._gc()
        key = (tenant or "", bot or "", session_id or "")
        now = self._now()
        ttl = float(ttl_seconds or _DEFAULT_TTL_SECS)
        entry = self._store.get(key)
        if entry is None or (now - entry.last) > entry.ttl:
            entry = RiskEntry(score=0.0, last=now, ttl=ttl)
        entry.score = max(0.0, entry.score + float(delta))
        entry.last = now
        entry.ttl = ttl
        self._store[key] = entry
        return entry.score

    def decay_and_get(
        self,
        tenant: str,
        bot: str,
        session_id: str,
        half_life_seconds: float = 180.0,
    ) -> float:
        key = (tenant or "", bot or "", session_id or "")
        entry = self._store.get(key)
        if not entry:
            return 0.0
        now = self._now()
        dt = max(0.0, now - entry.last)
        if half_life_seconds > 0:
            # Exponential decay toward 0
            decay = 0.5 ** (dt / half_life_seconds)
            entry.score *= decay
        entry.last = now
        self._store[key] = entry
        return entry.score

# Global singleton
_session_risk_store = SessionRiskStore()

def session_risk_store() -> SessionRiskStore:
    return _session_risk_store
