from pathlib import Path

ALERTS = Path("deploy/prometheus/alerts_trace_guard.yaml")
HEADER_LIMIT_ALERTS = Path("deploy/prometheus/alerts_header_limits.yaml")


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


def test_header_limit_alerts_file_exists() -> None:
    assert HEADER_LIMIT_ALERTS.exists(), "header limit alerts file is missing"


def test_header_limit_alerts_have_metric_snippets() -> None:
    text = HEADER_LIMIT_ALERTS.read_text(encoding="utf-8")
    assert "guardrail_ingress_header_limit_blocked_total" in text
    for name in [
        "HighHeaderCountBlocks",
        "HighHeaderValueLenBlocks",
        "HeaderLimitsBlocksGlobal",
    ]:
        assert name in text
