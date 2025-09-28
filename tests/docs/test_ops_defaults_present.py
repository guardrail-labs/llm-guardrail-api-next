import shlex
import subprocess
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


def test_env_example_is_sourceable() -> None:
    env_path = Path("deploy/examples/security_defaults.env")
    assert env_path.exists()
    # Source in bash and print selected vars to ensure values round-trip
    cmd = (
        f"set -a; source {shlex.quote(str(env_path))}; "
        "printf '%s\\n' \"$INGRESS_DUPLICATE_HEADER_GUARD_MODE\" "
        '"$INGRESS_DUPLICATE_HEADER_UNIQUE" '
        '"$INGRESS_DUPLICATE_HEADER_METRIC_ALLOWLIST" '
        '"$INGRESS_UNICODE_ENFORCE_FLAGS"'
    )
    out = subprocess.check_output(["bash", "-c", cmd], text=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert lines[0] == "log"
    # Ensure the long lists contain key tokens and no literal newlines
    assert "x-request-id" in lines[1]
    assert "\n" not in lines[1]
    assert "content-type" in lines[2]
    assert "\n" not in lines[2]
    assert lines[3] == "bidi,zwc"
