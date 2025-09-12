from __future__ import annotations

import asyncio

import pytest
from prometheus_client import CollectorRegistry

from app.observability.metrics import make_verifier_metrics
from app.services.verifier.result_types import VerifierOutcome
from app.services.verifier.router_adapter import VerifierAdapter


class _BoomProvider:
    name = "boom"

    async def evaluate(self, text: str) -> VerifierOutcome:
        raise RuntimeError("boom")


class _FlippyProvider:
    name = "flippy"

    def __init__(self) -> None:
        self.fail = True

    async def evaluate(self, text: str) -> VerifierOutcome:
        if self.fail:
            self.fail = False
            raise RuntimeError("fail")
        return VerifierOutcome(allowed=True, reason="ok")


def _sample_value(counter, provider: str) -> float:
    fam = list(counter.collect())[0]
    for s in fam.samples:
        if s.labels.get("provider") == provider:
            return float(s.value)
    return 0.0


def _gauge_value(gauge, provider: str) -> float:
    fam = list(gauge.collect())[0]
    for s in fam.samples:
        if s.labels.get("provider") == provider:
            return float(s.value)
    return 0.0


def test_circuit_open_increments_counter(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("VERIFIER_CB_RECOVERY_SECONDS", "30")
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    adapter = VerifierAdapter(_BoomProvider(), metrics=metrics)

    # First call trips the breaker
    asyncio.run(adapter.evaluate("x"))
    # Second call should be short-circuited
    out = asyncio.run(adapter.evaluate("y"))
    assert out.allowed is True and out.reason == "circuit_open"
    assert _sample_value(metrics.circuit_open_total, "boom") == 1.0


def test_provider_error_increments_error_total(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.delenv("VERIFIER_CB_ENABLED", raising=False)

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    adapter = VerifierAdapter(_BoomProvider(), metrics=metrics)

    asyncio.run(adapter.evaluate("x"))
    assert _sample_value(metrics.error_total, "boom") == 1.0


def test_gauge_flips_on_success_failure(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "2")
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    if metrics.circuit_state is None:
        pytest.skip("gauge unsupported")

    adapter = VerifierAdapter(_FlippyProvider(), metrics=metrics)
    # Failure -> gauge should be 1
    out_fail = asyncio.run(adapter.evaluate("a"))
    assert out_fail.allowed is True
    assert _gauge_value(metrics.circuit_state, "flippy") == 1.0
    # Success -> gauge should drop to 0
    out = asyncio.run(adapter.evaluate("b"))
    assert out.allowed is True and out.reason == "ok"
    assert _gauge_value(metrics.circuit_state, "flippy") == 0.0
