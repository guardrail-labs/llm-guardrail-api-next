from __future__ import annotations

import threading
import time
from typing import Dict, Tuple


class InMemoryTokenBucketStore:
    """
    Thread-safe, in-memory token-bucket storage.
    Key -> (tokens, last_refill_epoch_s)
    Use Redis for production multi-instance deployments.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._state: Dict[str, Tuple[float, float]] = {}

    def get(self, key: str) -> Tuple[float, float] | None:
        with self._lock:
            return self._state.get(key)

    def set(self, key: str, tokens: float, ts: float) -> None:
        with self._lock:
            self._state[key] = (tokens, ts)


class RateLimiter:
    """
    Token-bucket rate limiter (tenant/bot aware).
    - capacity: BURST size (max tokens)
    - fill_rate: tokens per second (PER_MINUTE / 60)
    Behavior:
      * When disabled: never block, but still compute/emit headers.
      * When enabled: decrement 1 token per request; if tokens < 1, block (429).
    """

    def __init__(self, store: InMemoryTokenBucketStore | None = None):
        self.store = store or InMemoryTokenBucketStore()

    @staticmethod
    def _key(tenant_id: str, bot_id: str) -> str:
        t = tenant_id or "unknown-tenant"
        b = bot_id or "*"
        return f"rl:{t}:{b}"

    def _refill(self, key: str, capacity: int, fill_rate: float, now: float) -> float:
        entry = self.store.get(key)
        if entry is None:
            tokens, last = float(capacity), now
        else:
            tokens, last = entry
            if tokens < 0:
                tokens = 0.0
            if fill_rate > 0:
                tokens = min(capacity, tokens + (now - last) * fill_rate)
        self.store.set(key, tokens, now)
        return tokens

    def check_and_consume(
        self,
        *,
        enabled: bool,
        tenant_id: str,
        bot_id: str,
        per_minute: int,
        burst: int,
        now: float | None = None,
    ) -> tuple[bool, int, int, int]:
        """
        Returns (allowed, remaining, limit, reset_epoch_s)
        - limit: logical per-minute limit
        - remaining: integer tokens rounded down for headers
        - reset_epoch_s: when bucket is expected to be full again
        """
        now = now or time.time()
        capacity = max(1, int(burst))
        limit = max(1, int(per_minute))
        fill_rate = limit / 60.0  # tokens per second

        key = self._key(tenant_id, bot_id)
        tokens = self._refill(key, capacity, fill_rate, now)

        if not enabled:
            # Non-blocking: simulate a consume for accurate Remaining; never 429.
            tokens_after = max(0.0, tokens - 1.0)
            self.store.set(key, tokens_after, now)
            remaining = int(tokens_after)
            # Time to full from current tokens
            deficit = capacity - tokens_after
            reset_in = int(deficit / fill_rate) if fill_rate > 0 else 0
            reset_epoch = int(now + max(0, reset_in))
            return True, remaining, limit, reset_epoch

        # Enforce
        if tokens >= 1.0:
            tokens_after = tokens - 1.0
            self.store.set(key, tokens_after, now)
            remaining = int(tokens_after)
            deficit = capacity - tokens_after
            reset_in = int(deficit / fill_rate) if fill_rate > 0 else 0
            reset_epoch = int(now + max(0, reset_in))
            return True, remaining, limit, reset_epoch

        # Block
        remaining = 0
        # When will at least 1 token be available?
        # Need (1 - tokens) / fill_rate seconds.
        needed = (1.0 - tokens) / fill_rate if fill_rate > 0 else 0
        reset_epoch = int(now + max(0, needed))
        return False, remaining, limit, reset_epoch
