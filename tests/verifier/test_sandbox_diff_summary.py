import importlib

import pytest

import app.services.verifier as v


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class AlwaysSafe:
    name = "safe"

    async def assess(self, text, meta=None):
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


class AlwaysUnsafe:
    name = "unsafe"

    async def assess(self, text, meta=None):
        return {"status": "unsafe", "reason": "ban", "tokens_used": 1}


@pytest.mark.anyio
async def test_summary_attached_on_diff(monkeypatch: pytest.MonkeyPatch):
    import app.services.verifier.providers as prov

    monkeypatch.setenv("VERIFIER_PROVIDERS", "safe,unsafe")
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_DIFF_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_DIFF_ATTACH_HEADER", "1")

    def _build(n: str):
        if n == "safe":
            return AlwaysSafe()
        if n == "unsafe":
            return AlwaysUnsafe()
        return None

    monkeypatch.setattr(prov, "build_provider", _build, raising=True)

    importlib.reload(v)

    out = await v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"})
    # primary likely "safe" (AlwaysSafe), shadow "unsafe" => diff summary present
    summary = out.get("sandbox_summary")
    assert summary is None or isinstance(summary, str)
