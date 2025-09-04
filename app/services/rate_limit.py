from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucket:
    """Simple in-memory token bucket for per-key rate limiting.

    Usage::
        b = TokenBucket(capacity=60, refill_per_sec=1.0)
        allowed = b.allow("api_key_hash")
    """

    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self._b: Dict[str, _Bucket] = {}

    def _now(self) -> float:
        return time.time()

    def _refill(self, key: str, now: float) -> None:
        b = self._b.get(key)
        if not b:
            self._b[key] = _Bucket(tokens=self.capacity, last=now)
            return
        elapsed = max(0.0, now - b.last)
        b.tokens = min(self.capacity, b.tokens + elapsed * self.refill)
        b.last = now

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._now()
        self._refill(key, now)
        b = self._b[key]
        if b.tokens >= cost:
            b.tokens -= cost
            return True
        return False

    def remaining(self, key: str) -> float:
        b = self._b.get(key)
        return 0.0 if not b else b.tokens


class RateLimiter:
    """
    Simple in-memory token-bucket rate limiter keyed by (tenant_id, bot_id).

    check_and_consume(...) returns a tuple:
      (allowed: bool, remaining: int, limit: int, reset_epoch: int)

    Notes:
    - When `enabled` is False, we never block but still emit headers.
    - `per_minute` tokens are added per minute, up to `burst`.
    - 1 token is consumed per request when enabled.
    """
    def __init__(self) -> None:
        # key -> (tokens, last_refill_ts)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.RLock()

    def _key(self, tenant_id: str, bot_id: str) -> str:
        t = (tenant_id or "").strip()
        b = (bot_id or "").strip()
        return f"{t}:{b}"

    def check_and_consume(
        self,
        *,
        enabled: bool,
        tenant_id: str,
        bot_id: str,
        per_minute: int,
        burst: int,
    ) -> Tuple[bool, int, int, int]:
        now = time.time()
        limit = max(1, int(burst or per_minute or 1))
        rate_per_sec = max(0.0, float(per_minute)) / 60.0

        # If disabled, never block; still present plausible headers.
        if not enabled:
            reset_epoch = int(now) + 60
            return True, limit, limit, reset_epoch

        key = self._key(tenant_id, bot_id)
        with self._lock:
            tokens, last = self._buckets.get(key, (float(limit), now))

            # Refill
            if rate_per_sec > 0.0:
                elapsed = max(0.0, now - last)
                tokens = min(float(limit), tokens + elapsed * rate_per_sec)

            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0

            # Compute reset: when 1 token will next be available if blocked,
            # otherwise one minute from now is fine for a coarse "window".
            if allowed:
                reset_epoch = int(now) + 60
            else:
                deficit = 1.0 - tokens
                wait = deficit / rate_per_sec if rate_per_sec > 0.0 else 60.0
                reset_epoch = int(now + max(0.0, wait))

            remaining = int(tokens) if tokens > 0 else 0
            self._buckets[key] = (tokens, now)

            return bool(allowed), remaining, limit, reset_epoch
