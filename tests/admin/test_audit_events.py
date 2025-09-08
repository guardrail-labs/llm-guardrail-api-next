import asyncio
import importlib

import pytest

import app.services.verifier as v

_events = []

def _fake_emit(event_type, payload):
    _events.append((event_type, payload))


@pytest.mark.asyncio
async def test_audit_emitted_on_timeout(monkeypatch):
    _events.clear()
    async def slow_verify_intent(text, ctx_meta):
        await asyncio.sleep(5)
        return {"status": "safe", "reason": "", "tokens_used": 10}
    monkeypatch.setattr(v, "verify_intent", slow_verify_intent)
    monkeypatch.setattr(v, "emit_audit_event", _fake_emit)
    monkeypatch.setenv("VERIFIER_TIMEOUT_MS", "50")
    importlib.reload(v)

    await v.verify_intent_hardened("x"*100, {"tenant_id": "t1", "bot_id": "b1"})
    types = [t for t, _ in _events]
    assert "verifier_timeout" in types or "verifier_fallback" in types
