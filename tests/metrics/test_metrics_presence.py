import re

from fastapi.testclient import TestClient

from app.main import create_app


def test_metrics_expose_custom_counters():
    client = TestClient(create_app())
    # Hit clarify to bump counter (if evaluate route/fixtures exist). Otherwise just query /metrics.
    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text
    # Presence checks (names only)
    assert re.search("guardrail_clarify_total", text)
    assert re.search("guardrail_egress_redactions_total", text)
