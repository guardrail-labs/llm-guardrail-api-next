import asyncio
import importlib
import sys
import types

import app.services.verifier as v
import app.services.verifier.providers as prov
import app.services.verifier.providers.anthropic_adapter as aa
import app.settings as settings


def test_anthropic_maps_unsafe(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "testkey")
    importlib.reload(settings)
    importlib.reload(prov)
    fake_mod = types.SimpleNamespace(Anthropic=lambda api_key: object())
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)

    async def fake_call(client, model, prompt):
        return {"label": "unsafe", "reason": "policy hit", "tokens_used": 7}

    monkeypatch.setattr(aa, "_call_anthropic_chat", fake_call)
    importlib.reload(v)
    out = asyncio.run(v.verify_intent("boom", {"tenant_id": "t", "bot_id": "b"}))
    assert out["status"] == "unsafe"
    assert out["provider"] == "anthropic"
