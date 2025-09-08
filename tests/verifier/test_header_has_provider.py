import asyncio
import importlib

import app.services.verifier as v


def _run(coro):
    return asyncio.run(coro)


def test_hardened_sets_provider_header(monkeypatch):
    async def fake(text, ctx):
        return {
            "status": "safe",
            "reason": "",
            "tokens_used": 3,
            "provider": "local_rules",
        }
    importlib.reload(v)
    monkeypatch.setattr(v, "verify_intent", fake)
    out, headers = _run(v.verify_intent_hardened("hi", {"tenant_id": "t", "bot_id": "b"}))
    assert headers.get("X-Guardrail-Verifier") == "local_rules"
