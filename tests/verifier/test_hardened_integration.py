import asyncio
from typing import Any, Dict, Tuple

from app.services.verifier.integration import maybe_verify_and_headers


def test_ingress_live_allow_sets_headers_and_action(monkeypatch):
    async def _fake(text: str, ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        return {"status": "safe", "reason": "ok", "provider": "p"}, {}

    monkeypatch.setenv("VERIFIER_HARDENED_MODE", "headers")
    monkeypatch.setattr("app.services.verifier.verify_intent_hardened", _fake)

    action, headers = asyncio.run(
        maybe_verify_and_headers(
            text="hi", direction="ingress", tenant_id="t", bot_id="b", family=None
        )
    )
    assert action == "allow"
    assert headers.get("X-Guardrail-Decision") == "allow"
    assert headers.get("X-Guardrail-Decision-Source") == "verifier-live"
    assert headers.get("X-Guardrail-Reason") == "ok"


def test_ingress_error_sets_fallback_headers_and_default_action(monkeypatch):
    async def _fake(text: str, ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        return {"status": "error", "provider": "p"}, {}

    monkeypatch.setenv("VERIFIER_HARDENED_MODE", "headers")
    monkeypatch.setenv("VERIFIER_DEFAULT_ACTION", "deny")
    monkeypatch.setattr("app.services.verifier.verify_intent_hardened", _fake)

    action, headers = asyncio.run(
        maybe_verify_and_headers(
            text="hi", direction="ingress", tenant_id="t", bot_id="b", family=None
        )
    )
    assert action == "deny"
    assert headers.get("X-Guardrail-Decision-Source") == "verifier-fallback"


def test_egress_uses_redacted_text_and_applies_live_deny(monkeypatch):
    captured: Dict[str, Any] = {}

    async def _fake(text: str, ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        captured["text"] = text
        captured["direction"] = ctx.get("direction")
        return {"status": "unsafe", "provider": "p"}, {}

    monkeypatch.setenv("VERIFIER_HARDENED_MODE", "headers")
    monkeypatch.setattr("app.services.verifier.verify_intent_hardened", _fake)

    action, headers = asyncio.run(
        maybe_verify_and_headers(
            text="redacted", direction="egress", tenant_id="t", bot_id="b", family=None
        )
    )
    assert action == "deny"
    assert captured["text"] == "redacted"
    assert captured["direction"] == "egress"
    assert headers.get("X-Guardrail-Decision") == "deny"


def test_hardened_off_sets_policy_only_source(monkeypatch):
    monkeypatch.setenv("VERIFIER_HARDENED_MODE", "off")
    action, headers = asyncio.run(
        maybe_verify_and_headers(
            text="hi", direction="ingress", tenant_id="t", bot_id="b", family=None
        )
    )
    assert action is None
    assert headers == {}
