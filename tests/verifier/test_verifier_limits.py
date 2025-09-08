import asyncio
import importlib

import pytest

import app.services.verifier as v


@pytest.mark.asyncio
async def test_ambiguous_maps_to_clarify_headers(monkeypatch):
    async def fake_verify_intent(text, ctx_meta):
        return {"status": "ambiguous", "reason": "not_sure", "tokens_used": 50}
    monkeypatch.setattr(v, "verify_intent", fake_verify_intent)

    outcome, headers = await v.verify_intent_hardened("hello", {"tenant_id": "t1", "bot_id": "b1"})
    assert outcome["status"] == "ambiguous"
    assert headers["X-Guardrail-Decision"] == "clarify_required"
    assert headers["X-Guardrail-Mode"] == "execute_locked"


@pytest.mark.asyncio
async def test_timeout_triggers_error_and_headers(monkeypatch):
    async def slow_verify_intent(text, ctx_meta):
        await asyncio.sleep(10)
        return {"status": "safe", "reason": "", "tokens_used": 10}
    monkeypatch.setattr(v, "verify_intent", slow_verify_intent)
    monkeypatch.setenv("VERIFIER_TIMEOUT_MS", "100")  # shrink for test
    importlib.reload(v)  # rebind enforcer with new timeout

    outcome, headers = await v.verify_intent_hardened("x"*100, {"tenant_id": "t1", "bot_id": "b1"})
    assert outcome["status"] == "error"
    assert outcome["reason"] in {"timeout", "unknown_error"}  # depending on timing
    assert headers["X-Guardrail-Decision"] == "block_input_only"
    assert headers["X-Guardrail-Mode"] == "execute_locked"


@pytest.mark.asyncio
async def test_budget_exhaustion_blocks(monkeypatch):
    async def fake_verify_intent(text, ctx_meta):
        # Spend 60k tokens per call to hit budget quickly
        return {"status": "safe", "reason": "", "tokens_used": 60000}
    monkeypatch.setattr(v, "verify_intent", fake_verify_intent)
    monkeypatch.setenv("VERIFIER_DAILY_TOKEN_BUDGET", "100000")
    importlib.reload(v)

    # first call ok (60k/100k)
    o1, _ = await v.verify_intent_hardened("a"*1000, {"tenant_id": "t2", "bot_id": "b2"})
    assert o1["status"] == "safe"

    # second call should exceed (120k/100k) and fall back to error→block
    o2, h2 = await v.verify_intent_hardened("b"*1000, {"tenant_id": "t2", "bot_id": "b2"})
    assert o2["status"] == "error"
    assert o2["reason"] in {"budget_exceeded", "limit_exceeded"}
    assert h2["X-Guardrail-Decision"] == "block_input_only"
