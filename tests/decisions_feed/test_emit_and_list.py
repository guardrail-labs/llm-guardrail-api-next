from __future__ import annotations

import threading
import time

import pytest
from starlette.testclient import TestClient

from app.services import decisions_bus
from app.main import create_app


def _make_client(monkeypatch: pytest.MonkeyPatch, tmp_path) -> TestClient:
    monkeypatch.setenv("ADMIN_UI_TOKEN", "demo")
    audit_path = tmp_path / "decisions.jsonl"
    decisions_bus.configure(path=str(audit_path), reset=True)
    app = create_app()
    return TestClient(app)


def test_decision_event_emitted_and_listed(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    client = _make_client(monkeypatch, tmp_path)
    resp = client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Debug": "1", "X-Tenant": "T1", "X-Bot": "B1"},
    )
    assert resp.status_code in (200, 403, 429)

    list_resp = client.get(
        "/admin/decisions",
        headers={"Authorization": "Bearer demo"},
    )
    assert list_resp.status_code == 200
    events = list_resp.json()
    assert events
    evt = events[0]
    assert evt["tenant"] == "T1"
    assert evt["bot"] == "B1"
    assert evt["endpoint"] == "/guardrail/evaluate"
    assert evt["family"] in {"allow", "deny"}
    assert isinstance(evt.get("rule_ids"), list)

    filtered = client.get(
        "/admin/decisions?tenant=missing",
        headers={"Authorization": "Bearer demo"},
    )
    assert filtered.status_code == 200
    assert filtered.json() == []


def test_export_csv_has_header(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    client = _make_client(monkeypatch, tmp_path)
    client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Debug": "1"},
    )
    resp = client.get(
        "/admin/decisions/export.csv",
        headers={"Authorization": "Bearer demo"},
    )
    assert resp.status_code == 200
    lines = resp.text.strip().splitlines()
    assert lines
    assert (
        lines[0]
        == "ts,incident_id,request_id,tenant,bot,family,mode,status,endpoint,rule_ids,policy_version,latency_ms"
    )


def test_sse_stream_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    client = _make_client(monkeypatch, tmp_path)
    status: list[int] = []

    def _reader() -> None:
        with client.stream(
            "GET",
            "/admin/decisions/stream?limit=1&once=1",
            headers={"Authorization": "Bearer demo"},
        ) as stream:
            status.append(stream.status_code)

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()
    client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Debug": "1"},
    )
    thread.join(timeout=5)
    assert status and status[0] == 200
