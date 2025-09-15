from importlib import reload

from starlette.testclient import TestClient


def test_actor_decisions_overflow_label(monkeypatch):
    monkeypatch.setenv("METRICS_LABEL_CARD_MAX", "2")
    from app.observability import metrics as obs_metrics

    reload(obs_metrics)

    from app.main import create_app

    app = create_app()
    client = TestClient(app)
    for idx in range(6):
        headers = {"X-Tenant": f"T{idx}", "X-Bot": f"B{idx}", "X-Debug": "1"}
        client.post("/guardrail/evaluate", json={"text": "hello"}, headers=headers)

    metrics_body = client.get("/metrics").text
    assert "guardrail_actor_decisions_total" in metrics_body
    assert "__overflow__" in metrics_body
