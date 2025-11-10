# Summary (PR-N): Validate CircuitBreaker transitions and timings.

from __future__ import annotations

import time

from app.services.circuit_breaker import BreakerConfig, CircuitBreaker


def test_opens_after_threshold_and_blocks() -> None:
    cb = CircuitBreaker(
        BreakerConfig(
            failure_threshold=3,
            recovery_seconds=60,
            half_open_max_calls=1,
        )
    )
    # initially closed, allow
    assert cb.state == "closed"
    assert cb.allow_call() is True
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    # threshold reached -> open
    assert cb.state == "open"
    assert cb.allow_call() is False  # blocks while open


def test_half_open_after_recovery_then_success_closes(monkeypatch) -> None:
    # short recovery for test
    cb = CircuitBreaker(
        BreakerConfig(
            failure_threshold=1,
            recovery_seconds=1,
            half_open_max_calls=1,
        )
    )
    assert cb.allow_call() is True
    cb.record_failure()
    assert cb.state == "open"

    # wait just over recovery
    time.sleep(1.1)
    # first call after cooldown should be allowed in half-open
    assert cb.allow_call() is True
    assert cb.state == "half_open"
    # success closes breaker
    cb.record_success()
    assert cb.state == "closed"
    assert cb.allow_call() is True  # normal again


def test_half_open_failure_reopens(monkeypatch) -> None:
    cb = CircuitBreaker(
        BreakerConfig(
            failure_threshold=1,
            recovery_seconds=1,
            half_open_max_calls=2,
        )
    )
    assert cb.allow_call() is True
    cb.record_failure()
    assert cb.state == "open"

    time.sleep(1.05)
    # we allow trial calls in half-open
    assert cb.allow_call() is True
    assert cb.state == "half_open"
    # a failure during half-open should reopen immediately
    cb.record_failure()
    assert cb.state == "open"
    # and block until next cooldown
    assert cb.allow_call() is False
