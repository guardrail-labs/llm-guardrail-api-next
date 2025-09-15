from starlette.testclient import TestClient


def test_actor_decisions_metric_emitted_with_headers():
    from app.main import create_app

    app = create_app()
    client = TestClient(app)
    headers = {"X-Tenant": "T1", "X-Bot": "B9", "X-Debug": "1"}
    response = client.post("/guardrail/evaluate", json={"text": "hello"}, headers=headers)
    assert response.status_code in (200, 400, 403, 429, 500)

    metrics_body = client.get("/metrics").text
    assert "guardrail_actor_decisions_total" in metrics_body
    assert 'family="' in metrics_body
    assert 'tenant="T1"' in metrics_body
    assert 'bot="B9"' in metrics_body
