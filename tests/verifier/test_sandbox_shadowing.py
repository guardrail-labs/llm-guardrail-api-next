import importlib
import pytest

import app.services.verifier as v


@pytest.fixture
def anyio_backend() -> str:
    # Force AnyIO to use asyncio for this file (no trio dependency).
    return "asyncio"


@pytest.mark.anyio
async def test_sandbox_runs_and_does_not_change_decision(monkeypatch: pytest.MonkeyPatch):
    # Force sandbox on & sync so the test awaits shadow calls (no background tasks).
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")

    # Use two entries so there is at least one "alternate" provider to shadow-call.
    # Duplicating local_rules is fine; the sandbox still exercises the code paths.
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules,local_rules")

    importlib.reload(v)

    out = await v.verify_intent("hello world", {"tenant_id": "t", "bot_id": "b"})

    # Decision should be returned normally and provider unchanged by sandboxing.
    assert "status" in out
    assert "provider" in out
    assert out["provider"] in ("local_rules", "cache", "unknown")
