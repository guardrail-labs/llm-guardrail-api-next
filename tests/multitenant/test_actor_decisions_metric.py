from starlette.testclient import TestClient


def test_actor_decisions_metric_emitted_with_headers():
    from app.main import create_app

    app = create_app()
    c = TestClient(app)

    headers = {"X-Tenant": "T1", "X-Bot": "B9", "X-Debug": "1"}
    r = c.post("/guardrail/evaluate", json={"text": "hello"}, headers=headers)
    assert r.status_code in (200, 400, 403, 429, 500)

    m = c.get("/metrics")
    body = m.text
    assert "guardrail_actor_decisions_total" in body
    assert '{family="' in body
    assert 'tenant="T1"' in body
    assert 'bot="B9"' in body
