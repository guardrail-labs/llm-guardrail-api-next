import importlib

import pytest

import app.services.verifier as v


class SlowOK:
    name = "slow"

    async def assess(self, text, meta=None):
        import asyncio
        await asyncio.sleep(0.01)
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


class FastTimeoutThenOK:
    name = "fast"

    def __init__(self) -> None:
        self.called = 0

    async def assess(self, text, meta=None):
        self.called += 1
        if self.called <= 2:
            import asyncio
            raise asyncio.TimeoutError()
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


@pytest.mark.anyio
async def test_adaptive_reranks_after_timeouts(monkeypatch):
    import app.services.verifier.provider_router as pr
    import app.services.verifier.providers as prov
    import app.settings as settings

    monkeypatch.setenv("VERIFIER_PROVIDERS", "fast,slow")
    monkeypatch.setenv("VERIFIER_ADAPTIVE_ROUTING_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_ADAPTIVE_MIN_SAMPLES", "2")
    monkeypatch.setenv("VERIFIER_PROVIDER_TIMEOUT_MS", "50")
    monkeypatch.setenv("VERIFIER_ADAPTIVE_STICKY_S", "0")
    monkeypatch.setattr(
        prov,
        "build_provider",
        lambda n: FastTimeoutThenOK()
        if n == "fast"
        else (SlowOK() if n == "slow" else None),
        raising=True,
    )

    importlib.reload(settings)
    importlib.reload(pr)
    importlib.reload(v)

    ctx = {"tenant_id": "T", "bot_id": "B"}
    _ = await v.verify_intent("x", ctx)
    _ = await v.verify_intent("x", ctx)
    out = await v.verify_intent("x", ctx)
    assert out["provider"] in ("slow", "cache")  # cache might hit if enabled


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"

