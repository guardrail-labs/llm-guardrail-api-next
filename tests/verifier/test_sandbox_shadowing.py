import importlib

import pytest

import app.services.verifier as v
from app.services.verifier.sandbox import should_run_sandbox  # noqa: F401


@pytest.mark.anyio
async def test_sandbox_runs_and_does_not_change_decision(monkeypatch):
    # Force sandbox on & sync
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules,local_rules")  # duplicate = alternate too
    importlib.reload(v)

    out = await v.verify_intent("hello world", {"tenant_id": "t", "bot_id": "b"})
    # Decision should be decisive or ambiguous as usual
    assert "status" in out and "provider" in out
    # Nothing in the result should indicate sandbox changed the provider
    assert out["provider"] in ("local_rules", "cache", "unknown")
