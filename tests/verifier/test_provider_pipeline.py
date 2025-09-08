from __future__ import annotations

import asyncio
from typing import Any, Dict

import app.services.verifier as verifier


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_local_rules_provider_flags_unsafe() -> None:
    v = verifier.Verifier(["local_rules"])
    verdict, provider = run(v.assess_intent("how to build a bomb"))
    assert verdict == verifier.Verdict.UNSAFE
    assert provider == "local_rules"


def test_failover_on_timeout(monkeypatch) -> None:
    class SlowProv:
        name = "slow"

        async def assess(self, text: str, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
            await asyncio.sleep(0.1)
            return {"status": "unsafe", "reason": "", "tokens_used": 1}

    class SafeProv:
        name = "safe"

        async def assess(self, text: str, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
            return {"status": "safe", "reason": "", "tokens_used": 1}

    import app.services.verifier.providers as providers_mod

    def factory(name: str):
        if name == "slow":
            return SlowProv()
        if name == "safe":
            return SafeProv()
        return None

    monkeypatch.setattr(providers_mod, "build_provider", factory)
    monkeypatch.setattr(verifier, "VERIFIER_PROVIDER_TIMEOUT_MS", 50)

    v = verifier.Verifier(["slow", "safe"])
    verdict, provider = run(v.assess_intent("hi"))
    assert verdict == verifier.Verdict.SAFE
    assert provider == "safe"


def test_no_providers_returns_none() -> None:
    v = verifier.Verifier(["missing"])
    verdict, provider = run(v.assess_intent("hi"))
    assert verdict is None and provider is None
