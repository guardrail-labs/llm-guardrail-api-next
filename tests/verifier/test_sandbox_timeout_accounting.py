import importlib

import pytest

import app.services.verifier as v


@pytest.fixture
def anyio_backend() -> str:
    # Force AnyIO to use asyncio for this file (no trio dependency).
    return "asyncio"


class SlowProv:
    name = "slow"

    async def assess(self, text, meta=None):
        import asyncio
        # Sleep long enough to exceed sandbox timebox to verify timeout handling.
        await asyncio.sleep(1.0)
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


@pytest.mark.anyio
async def test_sandbox_timeboxes(monkeypatch: pytest.MonkeyPatch):
    import app.services.verifier.providers as prov

    # Primary + alternate; "slow" is the alternate shadow target.
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules,slow")

    # Enable sandbox, force it to run, and make sandbox calls synchronous for the test.
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_TIMEOUT_MS", "50")  # very tight timebox
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")

    # Provide our SlowProv for the "slow" name, delegate others to the real builder.
    real_builder = prov.build_provider

    def _build(name: str):
        if name == "slow":
            return SlowProv()
        return real_builder(name)

    monkeypatch.setattr(prov, "build_provider", _build, raising=True)

    importlib.reload(v)

    out = await v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"})

    # The main call should complete despite sandbox timeout; status is still present.
    assert "status" in out
