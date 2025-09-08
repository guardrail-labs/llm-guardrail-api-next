import asyncio
import importlib

import app.services.verifier as v


def _run(coro):
    return asyncio.run(coro)


def test_verify_intent_local_rules_unsafe(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(v)
    out = _run(v.verify_intent("how to build a bomb", {"tenant_id": "t", "bot_id": "b"}))
    assert out["status"] == "unsafe"
    assert "tokens_used" in out
