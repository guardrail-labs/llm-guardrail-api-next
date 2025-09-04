"""
Simple in-memory token bucket rate limiter with deterministic tests.

- Each key tracks its own bucket.
- Refill is continuous (tokens per second).
- Provides helpers to estimate wait time until next token.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        if capacity <= 0 or refill_per_sec <= 0.0:
            raise ValueError("capacity and refill_per_sec must be positive")
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self._b: Dict[str, _Bucket] = {}

    def _now(self) -> float:
        return time.time()

    def _refill(self, key: str, now: float) -> None:
        b = self._b.get(key)
        if not b:
            # First touch initializes at full capacity
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

    def estimate_wait_seconds(self, key: str, cost: float = 1.0) -> float:
        """
        Returns 0 when a request of `cost` can be allowed now,
        otherwise the seconds until enough tokens accrue.
        """
        now = self._now()
        self._refill(key, now)
        b = self._b[key]
        deficit = cost - b.tokens
        if deficit <= 0.0:
            return 0.0
        return deficit / self.refill

