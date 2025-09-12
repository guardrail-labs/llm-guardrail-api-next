from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from app.services.verifier.budget import VerifierTimedOut, within_budget
from app.services.verifier.result_types import VerifierOutcome
from app.services.verifier.router_adapter import VerifierAdapter


@pytest.mark.anyio
async def test_within_budget_no_budget_runs() -> None:
    async def work() -> int:
        await asyncio.sleep(0.01)
        return 42

    val = await within_budget(lambda: work(), budget_ms=None)
    assert val == 42


@pytest.mark.anyio
async def test_within_budget_times_out() -> None:
    async def slow() -> str:
        await asyncio.sleep(0.05)
        return "done"

    with pytest.raises(VerifierTimedOut):
        await within_budget(lambda: slow(), budget_ms=1)


@dataclass
class _EchoAllowProvider:
    delay_ms: int = 0

    async def evaluate(self, text: str) -> VerifierOutcome:
        if self.delay_ms:
            await asyncio.sleep(self.delay_ms / 1000.0)
        return VerifierOutcome(allowed=True, reason="ok", provider="echo")


@pytest.mark.anyio
async def test_adapter_respects_sampling_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0")
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)
    adapter = VerifierAdapter(_EchoAllowProvider())
    out = await adapter.evaluate("hello")
    assert out.allowed is True
    assert "sampling=0.0" in out.reason


@pytest.mark.anyio
async def test_adapter_enforces_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "1")
    adapter = VerifierAdapter(_EchoAllowProvider(delay_ms=10))
    out = await adapter.evaluate("hello")
    assert out.allowed is True
    assert out.reason == "verifier_timeout_budget_exceeded"


@pytest.mark.anyio
async def test_adapter_normal_call_within_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "50")
    adapter = VerifierAdapter(_EchoAllowProvider(delay_ms=5))
    out = await adapter.evaluate("x")
    assert out.allowed is True
    assert out.reason == "ok"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
