from importlib import reload

from starlette.testclient import TestClient


def test_actor_decisions_overflow_label(monkeypatch):
    monkeypatch.setenv("METRICS_LABEL_CARDINALITY_MAX", "2")
    monkeypatch.setenv("METRICS_LABEL_PAIR_CARDINALITY_MAX", "2")
    monkeypatch.setenv("METRICS_LABEL_OVERFLOW", "__overflow__")

    from app.observability import metrics as obs_metrics

    reload(obs_metrics)

    from app.main import create_app

    app = create_app()
    c = TestClient(app)

    for i in range(6):
        headers = {"X-Tenant": f"T{i}", "X-Bot": f"B{i}", "X-Debug": "1"}
        c.post("/guardrail/evaluate", json={"text": "hello"}, headers=headers)

    body = c.get("/metrics").text
    assert "guardrail_actor_decisions_total" in body
    assert "__overflow__" in body, f"Expected overflow sentinel in metrics; got:\n{body[:1500]}"
