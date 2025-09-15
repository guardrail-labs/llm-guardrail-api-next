import prometheus_client
from fastapi.testclient import TestClient

from app.main import create_app


def test_expected_metric_names_registered():
    client = TestClient(create_app())
    client.get("/health")
    text = prometheus_client.generate_latest(prometheus_client.REGISTRY).decode("utf-8")
    expected = {
        "guardrail_requests_total",
        "guardrail_decisions_total",
        "guardrail_latency_seconds_bucket",
        "guardrail_latency_seconds_count",
        "guardrail_latency_seconds_sum",
    }
    missing = [n for n in expected if n not in text]
    assert not missing, f"Missing expected metrics: {missing}"
