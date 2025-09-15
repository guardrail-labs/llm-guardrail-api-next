from pathlib import Path


def test_alerts_contain_status_rules():
    s = Path("observability/alerts/guardrail-rules.yaml").read_text(encoding="utf-8")
    assert "guardrail_http_status_total{status=~\"5..\"}" in s
    assert "guardrail_http_status_total{status=\"429\"}" in s
