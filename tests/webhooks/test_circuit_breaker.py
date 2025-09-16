from __future__ import annotations

import itertools
from typing import Iterator

import pytest

from app.services.webhooks_cb import (
    CircuitBreaker,
    CircuitState,
    _KeyedCBRegistry,
    backoff_with_jitter,
    compute_backoff_ms,
)


def _fixed_random_seq(vals: Iterator[float]):
    def _r() -> float:
        return next(vals)

    return _r


def test_backoff_with_jitter_deterministic() -> None:
    rnd = _fixed_random_seq(itertools.repeat(0.5))
    assert backoff_with_jitter(200, 3, 10_000, rnd) == 1_600
    assert backoff_with_jitter(200, 8, 10_000, rnd) == 10_000


def test_compute_backoff_uses_cap() -> None:
    ms = compute_backoff_ms(200, 0)
    assert ms >= 100


def test_cb_transitions_open_halfopen_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    cb = CircuitBreaker(error_threshold=2, window=5, cooldown_sec=10)

    t = 1_000.0

    def fake_now() -> float:
        return t

    monkeypatch.setattr(cb, "_now", fake_now)

    assert cb.before_send() is True
    cb.after_failure()
    assert cb.before_send() is True
    cb.after_failure()
    assert cb.state() == CircuitState.OPEN
    assert cb.before_send() is False

    t += 9.0
    assert cb.state() == CircuitState.OPEN
    assert cb.before_send() is False

    t += 1.0
    assert cb.state() == CircuitState.HALF_OPEN
    assert cb.before_send() is True
    assert cb.before_send() is False

    cb.after_success()
    assert cb.state() == CircuitState.CLOSED
    assert cb.before_send() is True

    cb.after_failure()
    assert cb.state() == CircuitState.CLOSED


def test_keyed_registry_is_per_host() -> None:
    reg = _KeyedCBRegistry(error_threshold=1, window=3, cooldown_sec=5)

    t = 2_000.0

    def now() -> float:
        return t

    assert reg.should_dlq_now("https://a.example.com/hook", now=now()) is False
    reg.on_failure("https://a.example.com/hook", now=now())
    assert reg.should_dlq_now("https://a.example.com/hook", now=now()) is True

    assert reg.should_dlq_now("https://b.example.com/hook", now=now()) is False

    t += 6.0
    assert reg.state("https://a.example.com/hook", now=now()) == CircuitState.HALF_OPEN
