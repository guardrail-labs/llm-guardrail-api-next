import asyncio
import importlib
import types

import app.services.verifier as v


def run(coro):
    return asyncio.run(coro)


def test_breaker_opens_and_skips(monkeypatch):
    class FailingProv:
        name = "failing"

        async def assess(self, text, meta=None):
            import asyncio
            raise asyncio.TimeoutError()

    import app.services.verifier.providers as prov
    monkeypatch.setenv("VERIFIER_PROVIDERS", "failing,local_rules")
    monkeypatch.setitem(__import__("sys").modules, "anthropic", types.SimpleNamespace())
    monkeypatch.setenv("VERIFIER_PROVIDER_BREAKER_FAILS", "2")
    monkeypatch.setenv("VERIFIER_PROVIDER_BREAKER_WINDOW_S", "60")
    monkeypatch.setenv("VERIFIER_PROVIDER_BREAKER_COOLDOWN_S", "30")

    def build_provider(name: str):
        if name == "failing":
            return FailingProv()
        if name == "local_rules":
            from app.services.verifier.providers.local_rules import LocalRulesProvider
            return LocalRulesProvider()
        return None

    monkeypatch.setattr(prov, "build_provider", build_provider, raising=True)
    importlib.reload(v)

    run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    out3 = run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out3["provider"] in ("local_rules", "unknown")
