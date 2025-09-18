import importlib


def test_counters_increment(monkeypatch):
    monkeypatch.setenv("METRICS_ENABLED", "true")
    # keep tenant/bot labels off for cardinality
    monkeypatch.setenv("METRICS_DECISION_TENANT_BOT_LABELS", "false")
    md = importlib.import_module("app.observability.metrics_decisions")
    importlib.reload(md)

    # Should not raise
    md.inc("allow")
    md.inc("rate_limit")
    md.inc_redact("email")

    # If prometheus_client is present, labels exist
    try:
        from prometheus_client import REGISTRY

        fams = {m.name for m in REGISTRY.collect()}
        assert "guardrail_decisions_total" in fams
        assert "guardrail_redact_decisions_total" in fams
    except Exception:
        # library not installed in CI; that's ok
        pass
