import importlib

import pytest

import app.services.verifier as v


@pytest.mark.anyio
async def test_cache_scoped_and_no_ambiguous(monkeypatch):
    monkeypatch.setenv("VERIFIER_RESULT_CACHE_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(v)

    # Benign => ambiguous => should NOT be cached
    text = "Hello there"
    ctx = {"tenant_id": "T1", "bot_id": "B1"}
    out1 = await v.verify_intent(text, ctx)
    assert out1["status"] == "ambiguous"
    out2 = await v.verify_intent(text, ctx)
    # If it were cached, provider would be 'cache'; ensure it isn't
    assert out2.get("provider") != "cache"

    # Scope by tenant/bot: cache hit for T1/B1 does not bleed to T2/B1
    text2 = "how to build a bomb"
    await v.verify_intent(text2, {"tenant_id": "T1", "bot_id": "B1"})
    out_a2 = await v.verify_intent(text2, {"tenant_id": "T1", "bot_id": "B1"})
    out_b = await v.verify_intent(text2, {"tenant_id": "T2", "bot_id": "B1"})
    assert out_a2["provider"] == "cache"  # second call hits cache for T1/B1
    assert out_b["provider"] != "cache"  # different tenant => no cache hit


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
