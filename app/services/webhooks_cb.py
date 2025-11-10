from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, Optional
from urllib.parse import urlparse

try:  # pragma: no cover - exercised in tests
    from app.services.config_store import get_webhook_cb_tuning
except Exception:  # pragma: no cover - defensive fallback for runtime import issues

    def get_webhook_cb_tuning() -> Dict[str, int]:
        return {
            "webhook_cb_error_threshold": 8,
            "webhook_cb_window": 30,
            "webhook_cb_cooldown_sec": 60,
            "webhook_backoff_cap_ms": 10_000,
        }


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    error_threshold: int = 8
    window: int = 30
    cooldown_sec: int = 60

    _outcomes: Deque[bool] = field(default_factory=lambda: deque(maxlen=30))
    _opened_at: Optional[float] = None
    _half_open_inflight: bool = False

    def _now(self) -> float:
        return time.monotonic()

    def _set_window(self) -> None:
        if self._outcomes.maxlen != self.window:
            self._outcomes = deque(self._outcomes, maxlen=self.window)

    def state(self, now: Optional[float] = None) -> CircuitState:
        self._set_window()
        if self._opened_at is None:
            return CircuitState.CLOSED
        opened_at = self._opened_at
        current = self._now() if now is None else now
        if current - opened_at >= self.cooldown_sec:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    def before_send(self, now: Optional[float] = None) -> bool:
        state = self.state(now)
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.OPEN:
            return False
        if self._half_open_inflight:
            return False
        self._half_open_inflight = True
        return True

    def after_success(self) -> None:
        self._record(True)
        if self._opened_at is not None and self.state() == CircuitState.HALF_OPEN:
            self._close()
        self._half_open_inflight = False

    def after_failure(self, now: Optional[float] = None) -> None:
        self._record(False)
        state = self.state(now)
        if state == CircuitState.HALF_OPEN:
            self._open(now)
        else:
            if self._failures_in_window() >= self.error_threshold:
                self._open(now)
        self._half_open_inflight = False

    def _record(self, ok: bool) -> None:
        self._set_window()
        self._outcomes.append(ok)

    def _failures_in_window(self) -> int:
        return sum(1 for ok in self._outcomes if not ok)

    def _open(self, now: Optional[float] = None) -> None:
        self._opened_at = self._now() if now is None else now
        self._half_open_inflight = False

    def _close(self) -> None:
        self._opened_at = None
        self._half_open_inflight = False
        self._outcomes.clear()


def backoff_with_jitter(
    base_ms: int,
    attempt: int,
    cap_ms: int,
    rnd: Callable[[], float] = random.random,
) -> int:
    if attempt < 0:
        attempt = 0
    raw = base_ms * (2**attempt)
    capped = cap_ms if raw > cap_ms else raw
    factor = 0.5 + float(rnd())
    return int(capped * factor)


class _KeyedCBRegistry:
    def __init__(self, error_threshold: int, window: int, cooldown_sec: int) -> None:
        self._ct: Dict[str, CircuitBreaker] = {}
        self._error_threshold = error_threshold
        self._window = window
        self._cooldown = cooldown_sec

    def _key(self, url: str) -> str:
        return urlparse(url).netloc or "unknown"

    def _get(self, url: str) -> CircuitBreaker:
        key = self._key(url)
        cb = self._ct.get(key)
        if cb is None:
            cb = CircuitBreaker(
                error_threshold=self._error_threshold,
                window=self._window,
                cooldown_sec=self._cooldown,
            )
            self._ct[key] = cb
        else:
            cb.error_threshold = self._error_threshold
            cb.window = self._window
            cb.cooldown_sec = self._cooldown
        return cb

    def should_dlq_now(self, url: str, now: Optional[float] = None) -> bool:
        return not self._get(url).before_send(now)

    def on_success(self, url: str) -> None:
        self._get(url).after_success()

    def on_failure(self, url: str, now: Optional[float] = None) -> None:
        self._get(url).after_failure(now)

    def state(self, url: str, now: Optional[float] = None) -> CircuitState:
        return self._get(url).state(now)


_registry: Optional[_KeyedCBRegistry] = None


def _load_tuning() -> tuple[int, int, int, int]:
    tuning = get_webhook_cb_tuning()
    return (
        int(tuning.get("webhook_cb_error_threshold", 8)),
        int(tuning.get("webhook_cb_window", 30)),
        int(tuning.get("webhook_cb_cooldown_sec", 60)),
        int(tuning.get("webhook_backoff_cap_ms", 10_000)),
    )


def get_cb_registry() -> _KeyedCBRegistry:
    global _registry
    if _registry is None:
        error_threshold, window, cooldown, _ = _load_tuning()
        _registry = _KeyedCBRegistry(error_threshold, window, cooldown)
    else:
        error_threshold, window, cooldown, _ = _load_tuning()
        _registry._error_threshold = error_threshold
        _registry._window = window
        _registry._cooldown = cooldown
    return _registry


def compute_backoff_ms(base_ms: int, attempt: int) -> int:
    _, _, _, cap = _load_tuning()
    return backoff_with_jitter(base_ms, attempt, cap)


__all__ = [
    "CircuitBreaker",
    "CircuitState",
    "_KeyedCBRegistry",
    "backoff_with_jitter",
    "compute_backoff_ms",
    "get_cb_registry",
]
