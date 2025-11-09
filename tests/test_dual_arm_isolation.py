from __future__ import annotations

from typing import Any, Dict, Tuple

import pytest


@pytest.mark.parametrize("action,status", [("deny", 400), ("block", 400), ("lock", 400)])
def test_ingress_failure_does_not_disable_egress(client, monkeypatch, action, status):
    async def fake_ingress(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        decision = {"details": {}, "action": action, "mode": "block", "reason": "policy_deny"}
        return decision, ctx

    skipped_called: Dict[str, Any] = {}

    def fake_skipped() -> Dict[str, Any]:
        skipped_called[action] = True
        return {"details": {}, "action": "skipped", "mode": "skipped", "reason": "skipped"}

    monkeypatch.setattr("app.runtime.router._INGRESS_GUARD.run", fake_ingress)
    monkeypatch.setattr("app.runtime.router._EGRESS_GUARD.skipped", fake_skipped)

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.status_code == status
    assert resp.headers["X-Guardrail-Decision-Egress"] == "skipped"
    assert skipped_called[action] is True


def test_egress_failure_does_not_bypass_ingress(client, monkeypatch):
    async def ok_ingress(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        decision = {"details": {}, "action": "allow", "mode": "allow", "reason": "policy_allow"}
        return decision, ctx

    async def error_egress(ctx: Dict[str, Any]):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.runtime.router._INGRESS_GUARD.run", ok_ingress)
    monkeypatch.setattr("app.runtime.router._EGRESS_GUARD.run", error_egress)

    resp = client.post("/chat/completions", json={"text": "hello"})
    assert resp.status_code == 500
    assert resp.headers["X-Guardrail-Decision-Ingress"] == "allow"
    assert resp.headers["X-Guardrail-Decision-Egress"] == "error"
