from pathlib import Path


def test_ops_docs_and_examples_exist() -> None:
    assert Path("docs/ops/security_defaults.md").exists()
    assert Path("deploy/examples/security_defaults.env").exists()
    assert Path("deploy/examples/security_defaults.values.yaml").exists()
    assert Path("deploy/grafana/guardrail_security_overview.json").exists()


def test_ops_docs_contain_required_keys() -> None:
    txt = Path("docs/ops/security_defaults.md").read_text(encoding="utf-8")
    for key in [
        "ingress_duplicate_header_guard_mode",
        "ingress_header_limits_enabled",
        "ingress_unicode_sanitizer_enabled",
        "ingress_unicode_enforce_mode",
    ]:
        assert key in txt


def test_dashboard_contains_metrics() -> None:
    txt = Path("deploy/grafana/guardrail_security_overview.json").read_text(encoding="utf-8")
    for metric in [
        "guardrail_ingress_trace_invalid_traceparent_total",
        "guardrail_ingress_trace_request_id_generated_total",
        "guardrail_ingress_duplicate_header_blocked_total",
        "guardrail_ingress_duplicate_header_total",
        "guardrail_ingress_header_limit_blocked_total",
        "guardrail_ingress_unicode_flagged_total",
        "guardrail_ingress_unicode_blocked_total",
    ]:
        assert metric in txt
