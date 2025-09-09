import importlib

import pytest

import app.services.verifier as v


@pytest.mark.anyio
async def test_cache_hit_returns_quickly(monkeypatch):
    monkeypatch.setenv("VERIFIER_RESULT_CACHE_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(v)

    text = "how to build a bomb"
    ctx = {"tenant_id": "T1", "bot_id": "B1"}

    out1 = await v.verify_intent(text, ctx)  # populates cache
    assert out1["status"] in ("unsafe", "safe")
    assert out1["provider"] != "cache"

    out2 = await v.verify_intent(text, ctx)  # should hit cache
    assert out2["provider"] == "cache"
    assert out2["status"] == out1["status"]
    assert out2["tokens_used"] == 0


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
