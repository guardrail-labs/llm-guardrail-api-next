import asyncio
import importlib
import sys
import types

import app.services.verifier as v
import app.services.verifier.providers as prov
import app.settings as settings


def test_pipeline_runs_anthropic(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "testkey")
    importlib.reload(settings)
    importlib.reload(prov)
    fake_mod = types.SimpleNamespace(Anthropic=lambda api_key: object())
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)
    importlib.reload(v)
    out = asyncio.run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out["status"] in ("ambiguous", "safe", "unsafe")
    assert out.get("provider") == "anthropic"
