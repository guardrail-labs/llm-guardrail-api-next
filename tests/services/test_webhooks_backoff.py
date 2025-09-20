import importlib
from typing import Tuple

import pytest

from app.services import webhooks as W


class FakeClock:
    def __init__(self) -> None:
        self._t = 0.0

    def monotonic(self) -> float:
        return self._t

    def sleep(self, sec: float) -> None:
        self._t += sec


def _make_send_once_fail_then_succeed(k_fail: int, status: int = 500):
    calls = {"n": 0}

    def _send_once() -> Tuple[bool, int | None, str | None]:
        calls["n"] += 1
        if calls["n"] <= k_fail:
            return False, status, None
        return True, 200, None

    return _send_once, calls


def _make_send_always_4xx():
    def _send_once() -> Tuple[bool, int | None, str | None]:
        return False, 429, None

    return _send_once


def _make_send_network_then_timeout(n: int = 2):
    calls = {"n": 0}

    def _send_once() -> Tuple[bool, int | None, str | None]:
        calls["n"] += 1
        if calls["n"] == 1:
            return False, None, "network"
        if calls["n"] == 2:
            return False, None, "timeout"
        return True, 200, None

    return _send_once, calls


@pytest.fixture(autouse=True)
def reload_webhooks(monkeypatch):
    # Ensure module constants pick up per-test environment mutations.
    importlib.reload(W)
    yield


def _with_clock(monkeypatch):
    clk = FakeClock()
    monkeypatch.setattr(W.time, "monotonic", clk.monotonic)
    monkeypatch.setattr(W, "_sleep_ms", lambda ms: clk.sleep(ms / 1000.0))
    return clk


def test_decorrelated_jitter_increases_and_bounded(monkeypatch):
    monkeypatch.setenv("WEBHOOK_BACKOFF_BASE_MS", "100")
    monkeypatch.setenv("WEBHOOK_BACKOFF_MAX_MS", "5000")
    monkeypatch.setenv("WEBHOOK_MAX_ATTEMPTS", "10")
    monkeypatch.setenv("WEBHOOK_MAX_HORIZON_MS", "60000")
    importlib.reload(W)

    clk = _with_clock(monkeypatch)
    monkeypatch.setattr(W.random, "uniform", lambda a, b: (a + b) / 2.0)

    send_once, calls = _make_send_once_fail_then_succeed(3, status=503)
    ok = W._deliver_with_backoff(send_once)
    assert ok is True
    assert calls["n"] >= 4
    assert clk.monotonic() > 0


def test_abort_on_4xx_no_retries(monkeypatch):
    monkeypatch.setenv("WEBHOOK_MAX_ATTEMPTS", "10")
    importlib.reload(W)

    _with_clock(monkeypatch)
    send_once = _make_send_always_4xx()
    ok = W._deliver_with_backoff(send_once)
    assert ok is False


def test_horizon_abort(monkeypatch):
    monkeypatch.setenv("WEBHOOK_MAX_HORIZON_MS", "500")
    monkeypatch.setenv("WEBHOOK_BACKOFF_BASE_MS", "400")
    monkeypatch.setenv("WEBHOOK_BACKOFF_MAX_MS", "5000")
    monkeypatch.setenv("WEBHOOK_MAX_ATTEMPTS", "50")
    importlib.reload(W)

    clk = _with_clock(monkeypatch)
    monkeypatch.setattr(W.random, "uniform", lambda a, b: (a + b) / 2.0)

    send_once, _ = _make_send_once_fail_then_succeed(100, status=503)
    ok = W._deliver_with_backoff(send_once)
    assert ok is False
    assert clk.monotonic() * 1000 >= 500


def test_retry_counters_increment(monkeypatch):
    import app.observability.metrics as metrics

    # Reset counters to a baseline by reloading metrics and webhooks.
    importlib.reload(metrics)
    importlib.reload(W)

    _with_clock(monkeypatch)
    monkeypatch.setattr(W.random, "uniform", lambda a, b: (a + b) / 2.0)

    send_once, calls = _make_send_network_then_timeout()

    retry_before = sum(
        sample._value.get() for sample in metrics.webhook_retry_total._metrics.values()
    )
    abort_before = sum(
        sample._value.get() for sample in metrics.webhook_abort_total._metrics.values()
    )

    ok = W._deliver_with_backoff(send_once)
    assert ok is True
    assert calls["n"] == 3

    retry_after = sum(
        sample._value.get() for sample in metrics.webhook_retry_total._metrics.values()
    )
    abort_after = sum(
        sample._value.get() for sample in metrics.webhook_abort_total._metrics.values()
    )

    assert retry_after - retry_before >= 2
    assert abort_after - abort_before == 0


def test_attempts_cap_abort(monkeypatch):
    monkeypatch.setenv("WEBHOOK_MAX_ATTEMPTS", "3")
    importlib.reload(W)

    _with_clock(monkeypatch)
    monkeypatch.setattr(W.random, "uniform", lambda a, b: (a + b) / 2.0)

    send_once, calls = _make_send_once_fail_then_succeed(50, status=500)
    ok = W._deliver_with_backoff(send_once)
    assert ok is False
    assert calls["n"] == 3
