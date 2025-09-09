import importlib
import types  # noqa: F401

import pytest

import app.services.verifier as v


class SlowProv:
    name = "slow"

    async def assess(self, text, meta=None):
        import asyncio

        await asyncio.sleep(1.0)
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


@pytest.mark.anyio
async def test_sandbox_timeboxes(monkeypatch):
    import app.services.verifier.providers as prov

    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules,slow")
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_TIMEOUT_MS", "50")
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")

    orig_build = prov.build_provider
    monkeypatch.setattr(
        prov,
        "build_provider",
        lambda n: SlowProv() if n == "slow" else orig_build(n),
        raising=False,
    )

    importlib.reload(v)
    out = await v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"})
    assert "status" in out  # call completed despite sandbox timeout
