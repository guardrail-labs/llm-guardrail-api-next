import asyncio
from typing import Any, Dict, Tuple

from app.routes.guardrail import (
    _apply_hardened_error_fallback,
    _apply_hardened_override,
    _maybe_hardened,
)
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
    assert headers.get("X-Guardrail-Mode") == "live"


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
    assert headers.get("X-Guardrail-Mode") == "fallback"


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
    assert headers.get("X-Guardrail-Mode") == "live"


def test_hardened_off_sets_policy_only_source(monkeypatch):
    monkeypatch.setenv("VERIFIER_HARDENED_MODE", "off")
    action, headers = asyncio.run(
        maybe_verify_and_headers(
            text="hi", direction="ingress", tenant_id="t", bot_id="b", family=None
        )
    )
    assert action is None
    assert headers == {}


def test_retry_then_live_override(monkeypatch):
    calls: list[int | None] = []

    async def _fake(**kwargs):
        calls.append(kwargs.get("latency_budget_ms"))
        if len(calls) == 1:
            raise asyncio.TimeoutError
        return "deny", {"X-Guardrail-Verifier": "p"}

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "1")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "200")
    monkeypatch.setattr("app.routes.guardrail._maybe_hardened_verify", _fake)

    action, headers = asyncio.run(
        _maybe_hardened(
            text="hi", direction="ingress", tenant="t", bot="b", family=None
        )
    )
    assert action == "deny"
    assert headers.get("X-Guardrail-Verifier-Mode") == "live"
    assert len(calls) == 2 and calls[0] >= calls[1]


def test_all_timeouts_apply_error_fallback(monkeypatch):
    calls: list[int | None] = []

    async def _fake(**kwargs):
        calls.append(kwargs.get("latency_budget_ms"))
        raise asyncio.TimeoutError

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "1")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "200")
    monkeypatch.setenv("VERIFIER_ERROR_FALLBACK", "deny")
    monkeypatch.setattr("app.routes.guardrail._maybe_hardened_verify", _fake)

    hv_action, hv_headers = asyncio.run(
        _maybe_hardened(
            text="hi", direction="ingress", tenant="t", bot="b", family=None
        )
    )
    assert hv_action is None
    assert hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback"
    base = _apply_hardened_override("allow", hv_action)
    if hv_headers.get("X-Guardrail-Verifier-Mode") == "fallback":
        base = _apply_hardened_error_fallback(base)
    assert base == "deny"
    assert len(calls) == 2 and calls[0] >= calls[1]


def test_unsafe_no_retry(monkeypatch):
    calls: list[int | None] = []

    async def _fake(**kwargs):
        calls.append(kwargs.get("latency_budget_ms"))
        return "deny", {"X-Guardrail-Verifier": "p"}

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "2")
    monkeypatch.setattr("app.routes.guardrail._maybe_hardened_verify", _fake)

    action, headers = asyncio.run(
        _maybe_hardened(
            text="hi", direction="ingress", tenant="t", bot="b", family=None
        )
    )
    assert action == "deny"
    assert headers.get("X-Guardrail-Verifier-Mode") == "live"
    assert len(calls) == 1
