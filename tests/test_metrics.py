import importlib
import os

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"

    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)

    return TestClient(main.build_app())


def test_metrics_expose_counters_and_histogram():
    client = _make_client()

    # Trigger a request
    r = client.post("/guardrail", json={"prompt": "hello"}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200

    # Scrape metrics
    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text

    # Basic counters and histogram exist
    assert "guardrail_requests_total" in text
    assert "guardrail_decisions_total" in text
    assert "guardrail_latency_seconds_count" in text  # Histogram exposes *_count, *_sum, etc.


def test_request_id_header_present():
    client = _make_client()
    r = client.post("/guardrail", json={"prompt": "hi"}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200
    assert "X-Request-ID" in r.headers
    assert r.headers["X-Request-ID"]
