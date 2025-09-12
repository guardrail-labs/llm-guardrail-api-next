# tests/services/test_verifier_circuit_integration.py
# Summary (PR-O): Ensure adapter respects circuit breaker gating and recovery.

from __future__ import annotations

import asyncio
import importlib

import pytest

from app.services.verifier.types import VerifierOutcome


class _FailingProvider:
    async def evaluate(self, text: str) -> VerifierOutcome:
        raise RuntimeError("boom")


class _FlippyProvider:
    def __init__(self) -> None:
        self.fail = True

    async def evaluate(self, text: str) -> VerifierOutcome:
        if self.fail:
            raise RuntimeError("flippy")
        return VerifierOutcome(allowed=True, reason="ok")


@pytest.mark.asyncio
async def test_adapter_skips_when_circuit_open(monkeypatch) -> None:
    # Enable breaker with threshold=1 so the first failure opens it
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("VERIFIER_CB_RECOVERY_SECONDS", "30")
    # Make sure adapter picks up env on import/init
    import app.services.verifier.router_adapter as adapter_mod
    importlib.reload(adapter_mod)

    adapter = adapter_mod.VerifierAdapter(_FailingProvider(), 1.0, None)

    # First call fails -> breaker records failure and opens
    out1 = await adapter.evaluate("x")
    assert out1.allowed is True
    assert "verifier_error" in out1.reason

    # Next call should be skipped by the open breaker
    out2 = await adapter.evaluate("y")
    assert out2.allowed is True
    assert "circuit_open" in out2.reason


@pytest.mark.asyncio
async def test_adapter_half_open_recovers_after_cooldown(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("VERIFIER_CB_RECOVERY_SECONDS", "1")
    import app.services.verifier.router_adapter as adapter_mod
    importlib.reload(adapter_mod)

    prov = _FlippyProvider()
    adapter = adapter_mod.VerifierAdapter(prov, 1.0, None)

    # Trip the breaker
    out1 = await adapter.evaluate("x")
    assert out1.allowed is True and "verifier_error" in out1.reason

    # Wait for cooldown -> half-open
    await asyncio.sleep(1.1)

    # Now succeed to close the breaker
    prov.fail = False
    out2 = await adapter.evaluate("y")
    assert out2.allowed is True
    assert "circuit_open" not in out2.reason
    assert out2.reason == "ok"
