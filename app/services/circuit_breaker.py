# Summary (PR-N: reusable circuit breaker):
# - Small dependency-free circuit breaker for guarding flaky upstreams.
# - States: "closed" -> "open" (after N failures) -> "half_open" (after cooldown).
# - In half_open, allow up to M trial calls; success closes, failure re-opens.
# - Thread-safe enough for typical FastAPI usage; no external deps.
# - Env helpers included (disabled by default).
#
# Env (all optional; read via from_env()):
#   VERIFIER_CB_ENABLED            (bool; default: false)
#   VERIFIER_CB_FAILURE_THRESHOLD  (int;  default: 5)
#   VERIFIER_CB_RECOVERY_SECONDS   (int;  default: 30)
#   VERIFIER_CB_HALF_OPEN_MAX_CALLS(int;  default: 1)

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple


def _truthy(val: object | None, default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _clamp_int(
    val: object | None,
    default: int,
    minimum: int,
    maximum: Optional[int] = None,
) -> int:
    if val is None:
        return default
    try:
        x = int(float(str(val).strip()))
    except Exception:
        return default
    if x < minimum:
        return minimum
    if maximum is not None and x > maximum:
        return maximum
    return x


@dataclass(frozen=True)
class BreakerConfig:
    failure_threshold: int = 5
    recovery_seconds: int = 30
    half_open_max_calls: int = 1


class CircuitBreaker:
    """Simple count-based circuit breaker with half-open probing."""

    __slots__ = (
        "_cfg",
        "_state",
        "_failure_count",
        "_opened_at",
        "_half_open_calls",
        "_lock",
    )

    def __init__(self, config: BreakerConfig | None = None) -> None:
        self._cfg = config or BreakerConfig()
        # internal state
        self._state: str = "closed"
        self._failure_count: int = 0
        self._opened_at: float | None = None
        self._half_open_calls: int = 0
        self._lock = threading.Lock()

    # ---------------------- public API ----------------------

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def allow_call(self) -> bool:
        """Decide if a call is permitted now."""
        with self._lock:
            now = time.monotonic()
            if self._state == "open":
                if self._opened_at is None:
                    # shouldn't happen; self-heal
                    self._opened_at = now
                    return False
                if now - self._opened_at >= float(self._cfg.recovery_seconds):
                    # transition to half-open
                    self._state = "half_open"
                    self._half_open_calls = 0
                else:
                    return False

            if self._state == "half_open":
                if self._half_open_calls < max(1, self._cfg.half_open_max_calls):
                    self._half_open_calls += 1
                    return True
                return False

            # closed
            return True

    def record_success(self) -> None:
        with self._lock:
            if self._state == "half_open":
                # success closes the breaker
                self._state = "closed"
                self._failure_count = 0
                self._half_open_calls = 0
                self._opened_at = None
            elif self._state == "closed":
                # keep it clean
                self._failure_count = 0

    def record_failure(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._state == "half_open":
                # immediate reopen
                self._state = "open"
                self._opened_at = now
                self._failure_count = 0
                self._half_open_calls = 0
                return

            if self._state == "closed":
                self._failure_count += 1
                if self._failure_count >= max(1, self._cfg.failure_threshold):
                    self._state = "open"
                    self._opened_at = now
                    self._half_open_calls = 0
                    # keep failure_count for observability or reset? choose reset.
                    self._failure_count = 0

    # ---------------------- helpers ----------------------

    def describe(self) -> str:
        with self._lock:
            return (
                f"state={self._state} failures={self._failure_count} "
                f"opened_at={self._opened_at} half_open_calls={self._half_open_calls}"
            )


# ---------------------- env helpers (optional) ----------------------


def breaker_config_from_env() -> BreakerConfig:
    return BreakerConfig(
        failure_threshold=_clamp_int(os.getenv("VERIFIER_CB_FAILURE_THRESHOLD"), 5, 1, 1_000_000),
        recovery_seconds=_clamp_int(os.getenv("VERIFIER_CB_RECOVERY_SECONDS"), 30, 1, 86_400),
        half_open_max_calls=_clamp_int(os.getenv("VERIFIER_CB_HALF_OPEN_MAX_CALLS"), 1, 1, 1_000),
    )


def breaker_from_env() -> Tuple[bool, CircuitBreaker]:
    enabled = _truthy(os.getenv("VERIFIER_CB_ENABLED"), False)
    return enabled, CircuitBreaker(breaker_config_from_env())
