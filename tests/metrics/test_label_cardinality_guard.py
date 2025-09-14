import importlib

from prometheus_client import generate_latest


def test_label_cardinality_overflow(monkeypatch):
    monkeypatch.setenv("METRICS_LABEL_CARDINALITY_MAX", "2")
    import app.observability.metrics as metrics
    metrics = importlib.reload(metrics)

    for i in range(4):
        metrics.inc_verifier_router_rank(f"tenant{i}", "bot")

    text = generate_latest(metrics.REGISTRY).decode("utf-8")
    assert f'tenant="{metrics._METRICS_LABEL_OVERFLOW}"' in text

    monkeypatch.delenv("METRICS_LABEL_CARDINALITY_MAX", raising=False)
    importlib.reload(metrics)
