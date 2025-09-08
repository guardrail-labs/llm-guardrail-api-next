import asyncio
import importlib

import app.services.verifier as ver


def _run(coro):
    return asyncio.run(coro)


def test_verify_intent_failover_to_local(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "openai,local_rules")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    importlib.reload(ver)
    out = _run(ver.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out["status"] in ("ambiguous", "safe", "unsafe")
