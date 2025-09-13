from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_clarify_response_shape(monkeypatch):
    def fake_eval(text: str, want_debug: bool):
        return "ambiguous", {}, None

    monkeypatch.setattr(
        "app.routes.guardrail._evaluate_ingress_policy", fake_eval, raising=False
    )

    r = client.post("/guardrail/evaluate", json={"text": "??? ambiguous ???"})
    assert r.status_code in (422, 400)
    j = r.json()
    assert j["action"] == "clarify"
    assert "incident_id" in j
    assert isinstance(j.get("questions", []), list)
    assert r.headers.get("X-Guardrail-Decision") == "clarify"

