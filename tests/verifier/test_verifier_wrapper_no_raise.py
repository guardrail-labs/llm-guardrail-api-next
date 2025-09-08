import asyncio
import importlib

import app.services.verifier as v


def test_precheck_failure_returns_fallback(monkeypatch) -> None:
    # Force daily budget zero so precheck fails
    monkeypatch.setenv("VERIFIER_DAILY_TOKEN_BUDGET", "0")
    importlib.reload(v)
    outcome, headers = asyncio.run(
        v.verify_intent_hardened("hello", {"tenant_id": "t", "bot_id": "b"})
    )
    assert outcome["status"] == "error"
    assert headers["X-Guardrail-Decision"] in {
        "block_input_only",
        "clarify_required",
    }

