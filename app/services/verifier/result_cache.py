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
    def __init__(self, ttl_s: int) -> None:
        self._ttl = max(1, int(ttl_s))
        self._data: Dict[str, tuple[Outcome, float]] = {}
        self._lock = RLock()

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
            return outcome

    def set(self, key: str, outcome: Outcome) -> None:
        with self._lock:
            self._data[key] = (outcome, time.time())

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class _RedisCache:
    def __init__(self, url: str, ttl_s: int) -> None:
        self._ttl = max(1, int(ttl_s))
        self._cli = None
        try:
            import redis  # type: ignore
            self._cli = redis.from_url(url, decode_responses=True)
        except Exception:
            self._cli = None

    def get(self, key: str) -> Optional[Outcome]:
        if not self._cli:
            return None
        try:
            val = self._cli.get(key)
            if not val or val not in ("safe", "unsafe"):
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
