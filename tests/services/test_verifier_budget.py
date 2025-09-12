# tests/services/test_verifier_budget.py
# Summary (PR-D update 2):
# - Removes dependency on pytest-asyncio by running coroutines via asyncio.run().
# - Keeps deterministic sampling tests (injectable RNG) and budget behavior.

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from app.services.verifier.budget import within_budget, VerifierTimedOut
from app.services.verifier.result_types import VerifierOutcome
from app.services.verifier.router_adapter import VerifierAdapter


# --- Budget utility tests ----------------------------------------------------


def test_within_budget_no_budget_runs() -> None:
    async def work():
        await asyncio.sleep(0.01)
        return 42

    val = asyncio.run(within_budget(lambda: work(), budget_ms=None))
    assert val == 42


def test_within_budget_times_out() -> None:
    async def slow():
        await asyncio.sleep(0.05)
        return "done"

    with pytest.raises(VerifierTimedOut):
        asyncio.run(within_budget(lambda: slow(), budget_ms=1))


# --- Adapter tests -----------------------------------------------------------


@dataclass
class _ProbeProvider:
    delay_ms: int = 0
    calls: int = field(default=0, init=False)

    async def evaluate(self, text: str) -> VerifierOutcome:
        self.calls += 1
        if self.delay_ms:
            await asyncio.sleep(self.delay_ms / 1000.0)
        return VerifierOutcome(allowed=True, reason="ok", provider="probe")


def test_adapter_respects_sampling_zero(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0")
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)
    provider = _ProbeProvider()
    adapter = VerifierAdapter(provider, rng=lambda: 0.0)
    out = asyncio.run(adapter.evaluate("hello"))
    assert out.allowed is True
    assert "sampling=0.0" in out.reason
    assert provider.calls == 0


def test_adapter_probabilistic_sampling_skips_when_draw_ge_pct(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0.25")
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)
    provider = _ProbeProvider()
    adapter = VerifierAdapter(provider, rng=lambda: 0.99)
    out = asyncio.run(adapter.evaluate("x"))
    assert out.allowed is True
    assert out.reason.startswith("sampling=skip")
    assert provider.calls == 0


def test_adapter_probabilistic_sampling_calls_when_draw_lt_pct(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0.25")
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)
    provider = _ProbeProvider()
    adapter = VerifierAdapter(provider, rng=lambda: 0.10)
    out = asyncio.run(adapter.evaluate("y"))
    assert out.allowed is True
    assert out.reason == "ok"
    assert provider.calls == 1


def test_adapter_enforces_budget_on_sampled(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "1")
    provider = _ProbeProvider(delay_ms=10)
    adapter = VerifierAdapter(provider, rng=lambda: 0.0)
    out = asyncio.run(adapter.evaluate("hello"))
    # On timeout we default to allowed=True to avoid changing external behavior
    assert out.allowed is True
    assert out.reason == "verifier_timeout_budget_exceeded"
    # Provider call count depends on exact timing; no assertion here.


def test_adapter_normal_call_within_budget(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "50")
    provider = _ProbeProvider(delay_ms=5)
    adapter = VerifierAdapter(provider, rng=lambda: 0.0)
    out = asyncio.run(adapter.evaluate("z"))
    assert out.allowed is True
    assert out.reason == "ok"
    assert provider.calls == 1
