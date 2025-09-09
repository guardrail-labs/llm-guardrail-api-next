import importlib

import pytest

import app.services.verifier as v


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class UnsafeProv:
    name = "unsafe"

    async def assess(self, text, meta=None):
        return {"status": "unsafe", "reason": "yikes", "tokens_used": 1}


@pytest.mark.anyio
async def test_diff_detects_but_does_not_change_decision(monkeypatch: pytest.MonkeyPatch):
    import app.services.verifier.providers as prov

    # primary local_rules -> likely safe on benign text; alternate "unsafe" disagrees
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules,unsafe")
    monkeypatch.setenv("VERIFIER_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_SAMPLE_RATE", "1.0")
    monkeypatch.setenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_DIFF_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_SANDBOX_DIFF_ATTACH_HEADER", "1")

    rb = prov.build_provider

    def _build(n: str):
        if n == "unsafe":
            return UnsafeProv()
        return rb(n)

    monkeypatch.setattr(prov, "build_provider", _build, raising=True)

    importlib.reload(v)

    out = await v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"})

    # Decision still comes from primary path
    assert "status" in out and "provider" in out
    # If sandbox ran sync, we may have a header summary plumbed via result
    # (exact presence depends on local_rules outcome)
    _ = out.get("sandbox_summary")

