import asyncio
import importlib

import app.services.policy as policy
import app.services.verifier as verifier


class SlowProvider:
    name = "slow"

    async def assess(self, text, meta=None):
        await asyncio.sleep(0.01)
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


def run(coro):
    return asyncio.run(coro)


def test_timeout_budget(monkeypatch):
    monkeypatch.setenv("VERIFIER_PROVIDERS", "slow")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "1")

    monkeypatch.setattr(
        "app.services.verifier.providers.build_provider",
        lambda name: SlowProvider() if name == "slow" else None,
        raising=True,
    )
    importlib.reload(verifier)

    out = run(verifier.verify_intent("hi", {"tenant_id": "t", "bot_id": "b"}))
    assert out["status"] == "timeout"
    decision, mode = policy.map_verifier_outcome_to_headers(out)
    assert decision == "clarify"
