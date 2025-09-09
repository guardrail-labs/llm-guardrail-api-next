from __future__ import annotations

import time
from threading import RLock
from typing import Dict, Optional

from app.settings import (
    VERIFIER_RESULT_CACHE_ENABLED,
    VERIFIER_RESULT_CACHE_URL,
    VERIFIER_RESULT_CACHE_TTL_SECONDS,
)

Outcome = str  # "safe" | "unsafe"


class _MemCache:
    """
    Simple in-process TTL cache.
    - Drops expired entries on read for the accessed key.
    - Also performs a periodic sweep on writes to avoid unbounded growth
      when keys are never read again.
    """

    def __init__(self, ttl_s: int, prune_interval_s: float = 5.0) -> None:
        self._ttl = max(1, int(ttl_s))
        self._data: Dict[str, tuple[Outcome, float]] = {}
        self._lock = RLock()
        self._prune_interval_s = float(prune_interval_s)
        self._last_prune_ts: float = time.time()

    def _prune_expired(self, now: float) -> None:
        """Remove all expired entries. Called periodically under the lock."""
        expired_keys = [
            k for k, (_outcome, ts) in self._data.items() if now - ts > self._ttl
        ]
        for k in expired_keys:
            self._data.pop(k, None)

    def _maybe_prune(self, now: float) -> None:
        if (now - self._last_prune_ts) >= self._prune_interval_s:
            self._prune_expired(now)
            self._last_prune_ts = now

    def get(self, key: str) -> Optional[Outcome]:
        now = time.time()
        with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            outcome, ts = v
            if now - ts > self._ttl:
                self._data.pop(key, None)
                return None
            # Opportunistic periodic sweep on reads, too.
            self._maybe_prune(now)
            return outcome

    def set(self, key: str, outcome: Outcome) -> None:
        now = time.time()
        with self._lock:
            # Periodic sweep on writes ensures TTL actually bounds memory.
            self._maybe_prune(now)
            self._data[key] = (outcome, now)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class _RedisCache:
    def __init__(self, url: str, ttl_s: int) -> None:
        self._ttl = max(1, int(ttl_s))
        self._cli = None
        try:
            import redis  # noqa: F401
            self._cli = redis.from_url(url, decode_responses=True)
        except Exception:
            self._cli = None

    def get(self, key: str) -> Optional[Outcome]:
        if not self._cli:
            return None
        try:
            val = self._cli.get(key)
            # mypy: ensure val is a str before returning
            if not isinstance(val, str):
                return None
            if val not in ("safe", "unsafe"):
                return None
            return val
        except Exception:
            return None

    def set(self, key: str, outcome: Outcome) -> None:
        if not self._cli:
            return
        try:
            self._cli.setex(key, self._ttl, outcome)
        except Exception:
            return


class ResultCache:
    """
    Hybrid cache: Redis (if configured) + process memory.
    We never cache 'ambiguous'. Keys are caller-defined strings.
    """

    def __init__(self, url: str, ttl_s: int) -> None:
        self._ttl = int(ttl_s)
        self._mem = _MemCache(ttl_s)
        self._redis = _RedisCache(url, ttl_s) if url else None

    def get(self, key: str) -> Optional[Outcome]:
        out = self._mem.get(key)
        if out is not None:
            return out
        if self._redis:
            out = self._redis.get(key)
            if out is not None:
                self._mem.set(key, out)
                return out
        return None

    def set(self, key: str, outcome: Outcome) -> None:
        if outcome not in ("safe", "unsafe"):
            return
        self._mem.set(key, outcome)
        if self._redis:
            self._redis.set(key, outcome)

    # ---- test/dev helpers ----
    def reset_memory(self) -> None:
        """Clear only the in-process cache (keeps Redis intact)."""
        self._mem = _MemCache(self._ttl)


ENABLED = VERIFIER_RESULT_CACHE_ENABLED
CACHE = ResultCache(VERIFIER_RESULT_CACHE_URL, VERIFIER_RESULT_CACHE_TTL_SECONDS)


def reset_memory() -> None:
    """Public helper: clear only in-process cache."""
    try:
        CACHE.reset_memory()
    except Exception:
        pass


def cache_key(tenant: str, bot: str, fp: str, policy_version: str) -> str:
    t = tenant or "unknown-tenant"
    b = bot or "unknown-bot"
    pv = policy_version or "unknown-policy"
    return f"veri:v1:{t}:{b}:{pv}:{fp}"
