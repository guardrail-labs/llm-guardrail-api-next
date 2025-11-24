from __future__ import annotations

import importlib

from starlette.testclient import TestClient

from app.services import decisions_bus


def test_confusable_detection_pipeline(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SANITIZER_CONFUSABLES_ENABLED", "true")

    import app.settings as settings

    importlib.reload(settings)
    assert settings.SANITIZER_CONFUSABLES_ENABLED is True

    import app.middleware.unicode_normalize_guard as normalize_guard

    importlib.reload(normalize_guard)

    import app.middleware.unicode_middleware as unicode_middleware

    importlib.reload(unicode_middleware)

    import app.routes.guardrail as guardrail_routes

    importlib.reload(guardrail_routes)

    import app.main as app_main

    importlib.reload(app_main)

    from app.observability import metrics as obs_metrics

    obs_metrics._sanitizer_confusables_detected_total.clear()
    decisions_bus.configure(path=str(tmp_path / "decisions.jsonl"), reset=True)

    app = app_main.create_app()
    client = TestClient(app)

    payload = {"text": "pa\u200bss Ａ"}
    resp = client.post("/guardrail/evaluate", json=payload)
    assert resp.status_code == 200

    samples = obs_metrics._sanitizer_confusables_detected_total.collect()[0].samples
    counts = {}
    for sample in samples:
        if sample.name == "guardrail_sanitizer_confusables_detected_total":
            counts[sample.labels.get("type")] = sample.value
    assert counts.get("zero_width") == 1
    assert counts.get("fullwidth") == 1

    events = decisions_bus.snapshot()
    assert events
    findings = events[-1].get("unicode_findings")
    assert findings
    assert findings["totals_by_type"].get("zero_width") == 1
    assert findings["totals_by_type"].get("fullwidth") == 1
    sample_chars = findings.get("sample_chars", {})
    assert sample_chars.get("zero_width", {}).get("codepoint") == "U+200B"
    assert sample_chars.get("fullwidth", {}).get("codepoint") == "U+FF21"
