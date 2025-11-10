from fastapi.testclient import TestClient


def test_rule_ids_propagate_to_headers(monkeypatch):
    def fake_eval(text: str, want_debug: bool):
        return "deny", {"policy:deny:test": ["match"]}, None

    monkeypatch.setattr("app.routes.guardrail._evaluate_ingress_policy", fake_eval, raising=False)
    monkeypatch.setattr("app.services.escalation.is_enabled", lambda: False, raising=False)

    from app.main import create_app

    app = create_app()
    client = TestClient(app)

    response = client.post("/guardrail/evaluate", json={"text": "anything"})
    header_value = response.headers.get("X-Guardrail-Rule-IDs")
    assert header_value is not None
    parts = {p.strip() for p in header_value.split(",") if p.strip()}
    assert "policy:deny:test" in parts
