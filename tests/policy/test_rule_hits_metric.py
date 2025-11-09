from fastapi.testclient import TestClient


def test_rule_hits_metric_emitted(monkeypatch):
    def fake_eval(text: str, want_debug: bool):
        return "deny", {"policy:deny:test": ["match"]}, None

    monkeypatch.setattr("app.routes.guardrail._evaluate_ingress_policy", fake_eval, raising=False)
    monkeypatch.setattr("app.services.escalation.is_enabled", lambda: False, raising=False)

    from app.main import create_app

    app = create_app()
    client = TestClient(app)

    client.post("/guardrail/evaluate", json={"text": "anything"})

    metrics_text = client.get("/metrics").text
    assert "guardrail_rule_hits_total" in metrics_text
    assert 'rule_id="policy:deny:test"' in metrics_text
    assert 'action="deny"' in metrics_text
    assert 'mode="deny"' in metrics_text
