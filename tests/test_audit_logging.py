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


def test_audit_event_emitted_with_truncation(monkeypatch):
    os.environ["AUDIT_ENABLED"] = "true"
    os.environ["AUDIT_SAMPLE_RATE"] = "1.0"
    os.environ["AUDIT_MAX_TEXT_CHARS"] = "24"

    captured = {}

    def fake_emit(event: dict) -> None:
        captured.update(event)

    monkeypatch.setattr("app.routes.guardrail.emit_audit_event", fake_emit)

    client = _make_client()

    payload = {"prompt": "A" * 200}
    r = client.post("/guardrail", json=payload, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200

    assert captured.get("decision") in ("allow", "block")
    assert captured.get("payload_bytes") == len("A" * 200)
    assert captured.get("sanitized_bytes") == len("A" * 200)
