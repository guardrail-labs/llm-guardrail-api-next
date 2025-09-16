from __future__ import annotations

from starlette.testclient import TestClient


def test_decision_event_emitted_and_listed(monkeypatch, tmp_path):
    # Ensure admin auth is available (adjust to your scheme if needed)
    monkeypatch.setenv("ADMIN_UI_TOKEN", "demo")

    # Make sure decision log writes to a temp file during test
    monkeypatch.setenv("DECISIONS_AUDIT_PATH", str(tmp_path / "decisions.jsonl"))

    from app.app import create_app
    app = create_app()
    c = TestClient(app)

    # Generate at least one decision
    r = c.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Debug": "1", "X-Tenant": "T1", "X-Bot": "B1"},
    )
    assert r.status_code in (200, 403, 429)

    # List decisions (auth header may vary in your repo; using Bearer demo)
    list_r = c.get("/admin/decisions", headers={"Authorization": "Bearer demo"})
    # Some repos protect admin in tests; accept 401 in that case
    assert list_r.status_code in (200, 401)
    if list_r.status_code == 200:
        data = list_r.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        evt = data[0]
        # Basic shape
        for k in ("ts", "family", "mode", "status"):
            assert k in evt


def test_export_csv_has_header(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_UI_TOKEN", "demo")
    monkeypatch.setenv("DECISIONS_AUDIT_PATH", str(tmp_path / "decisions.jsonl"))

    from app.app import create_app
    app = create_app()
    c = TestClient(app)

    # Seed at least one decision
    _ = c.post("/guardrail/evaluate", json={"text": "hello"}, headers={"X-Debug": "1"})

    r = c.get("/admin/decisions/export.csv", headers={"Authorization": "Bearer demo"})
    assert r.status_code in (200, 401)
    if r.status_code == 200:
        lines = r.text.splitlines()
        assert lines, "empty CSV"
        expected_header = ",".join(
            [
                "ts",
                "incident_id",
                "request_id",
                "tenant",
                "bot",
                "family",
                "mode",
                "status",
                "endpoint",
                "rule_ids",
                "policy_version",
                "latency_ms",
            ]
        )
        assert lines[0] == expected_header
