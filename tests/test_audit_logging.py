import importlib
import json
import logging
import os

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"

    import app.config as cfg
    importlib.reload(cfg)
    import app.main as main
    importlib.reload(main)

    return TestClient(main.build_app())


def test_audit_event_emitted_with_truncation(caplog):
    # Force audit on and always sample, with tiny snippet size
    os.environ["AUDIT_ENABLED"] = "true"
    os.environ["AUDIT_SAMPLE_RATE"] = "1.0"
    os.environ["AUDIT_MAX_TEXT_CHARS"] = "24"

    client = _make_client()

    caplog.set_level(logging.INFO, logger="guardrail_audit")

    payload = {"prompt": "A" * 200}
    r = client.post("/guardrail", json=payload, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200

    # Find an audit log line
    records = [rec for rec in caplog.records if rec.name == "guardrail_audit"]
    assert records, "No audit log records captured"

    # Parse JSON and verify fields
    event = json.loads(records[-1].msg)
    assert event["event"] == "guardrail_decision"
    assert isinstance(event["request_id"], str)
    assert event["snippet_len"] <= 24
    assert event["snippet_truncated"] is True
    assert event["decision"] in ("allow", "block")

