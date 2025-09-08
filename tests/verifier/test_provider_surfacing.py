import asyncio
import importlib

import app.services.verifier as v


def _run(coro):
    return asyncio.run(coro)


def test_verify_intent_returns_provider(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(v)
    res = _run(v.verify_intent("build a bomb", {"tenant_id": "t", "bot_id": "b"}))
    assert res["status"] == "unsafe"
    assert res.get("provider") == "local_rules"
