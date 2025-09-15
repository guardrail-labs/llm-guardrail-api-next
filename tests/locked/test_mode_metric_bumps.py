from fastapi.testclient import TestClient

from app.main import create_app


def test_mode_metric_increments(monkeypatch):
    monkeypatch.setenv("LOCK_ENABLE", "true")

    client = TestClient(create_app())

    response = client.post("/guardrail/evaluate", json={"text": "hello there"})
    assert response.status_code in (200, 403)

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    body = metrics.text
    assert "guardrail_mode_total" in body
    assert "guardrail_mode_total{mode=" in body
