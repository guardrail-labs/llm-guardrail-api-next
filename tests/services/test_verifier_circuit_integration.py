# tests/services/test_verifier_circuit_integration.py
# Summary: Circuit-breaker integration tests without pytest-asyncio.
# - Uses asyncio.run(...) inside plain sync tests.
# - Enables CB via env and forces full sampling for determinism.

from __future__ import annotations

import asyncio
import importlib
import time

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


def _reload_adapter():
    import app.services.verifier.router_adapter as adapter_mod

    importlib.reload(adapter_mod)
    return adapter_mod


def test_adapter_skips_when_circuit_open(monkeypatch) -> None:
    # Enable breaker: 1 failure opens the circuit; no immediate recovery
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("VERIFIER_CB_RECOVERY_SECONDS", "30")
    # Ensure verifier is always sampled
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")

    adapter_mod = _reload_adapter()
    adapter = adapter_mod.VerifierAdapter(_FailingProvider())

    # First call should fail the provider and open the circuit
    out1 = asyncio.run(adapter.evaluate("x"))
    assert out1.allowed is True
    assert "verifier_error" in out1.reason

    # Second call should be short-circuited by the open circuit
    out2 = asyncio.run(adapter.evaluate("y"))
    assert out2.allowed is True
    assert "circuit_open" in out2.reason


def test_adapter_half_open_recovers_after_cooldown(monkeypatch) -> None:
    # Short cooldown to reach half-open quickly
    monkeypatch.setenv("VERIFIER_CB_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_CB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("VERIFIER_CB_RECOVERY_SECONDS", "1")
    # Ensure verifier is always sampled
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")

    adapter_mod = _reload_adapter()

    prov = _FlippyProvider()
    adapter = adapter_mod.VerifierAdapter(prov)

    # Trip the circuit
    out1 = asyncio.run(adapter.evaluate("x"))
    assert out1.allowed is True and "verifier_error" in out1.reason

    # After cooldown, breaker should allow a trial call (half-open)
    time.sleep(1.1)

    # Make provider succeed and confirm breaker closes on success
    prov.fail = False
    out2 = asyncio.run(adapter.evaluate("y"))
    assert out2.allowed is True
    assert out2.reason == "ok"
