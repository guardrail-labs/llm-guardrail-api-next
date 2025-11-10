import random

from fastapi.testclient import TestClient


def test_policy_lock_maps_to_execute_locked_when_enabled(monkeypatch):
    monkeypatch.setenv("LOCK_ENABLE", "true")

    def fake_eval(text: str, want_debug: bool):
        return "allow", {"policy:allow:test": ["match"]}, None

    def fake_route(decision: dict, *, text: str):
        updated = dict(decision)
        updated["action"] = "lock"
        updated.setdefault("rule_hits", decision.get("rule_hits", {}))
        updated["rule_ids"] = ["LOCK-TST"]
        return updated

    monkeypatch.setattr("app.routes.guardrail._evaluate_ingress_policy", fake_eval, raising=False)
    monkeypatch.setattr("app.routes.guardrail._verifier_sampling_pct", lambda: 1.0)
    monkeypatch.setattr("app.routes.guardrail._hits_trigger_verifier", lambda _: True)
    monkeypatch.setattr(random, "random", lambda: 0.0)
    monkeypatch.setattr("app.routes.guardrail.maybe_route_to_verifier", fake_route, raising=False)
    monkeypatch.setattr("app.services.escalation.is_enabled", lambda: False, raising=False)

    from app.main import create_app

    app = create_app()
    client = TestClient(app)

    response = client.post("/guardrail/evaluate", json={"text": "trigger lock"})
    assert response.status_code == 200
    assert response.headers.get("X-Guardrail-Mode") == "execute_locked"
