from pathlib import Path

ALERTS = Path("deploy/prometheus/alerts_trace_guard.yaml")


def test_alert_file_exists() -> None:
    assert ALERTS.exists(), "alerts file is missing"


def test_contains_required_alert_names() -> None:
    text = ALERTS.read_text(encoding="utf-8")
    # minimal presence checks; avoids adding YAML deps
    for name in [
        "HighInvalidTraceparentRate",
        "HighInvalidTraceparentRateGlobal",
        "HighRequestIdGenerationRate",
        "HighRequestIdGenerationRateGlobal",
    ]:
        assert name in text


def test_contains_key_metric_snippets() -> None:
    text = ALERTS.read_text(encoding="utf-8")
    assert "guardrail_ingress_trace_invalid_traceparent_total" in text
    assert "guardrail_ingress_trace_request_id_generated_total" in text
