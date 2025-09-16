from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.config_store import get_config, reset_config, set_config


@pytest.fixture()
def admin_history_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[TestClient, str]]:
    token = "secret-token"
    audit_path = tmp_path / "config_audit.jsonl"
    monkeypatch.setenv("ADMIN_UI_TOKEN", token)
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(audit_path))
    reset_config()
    if audit_path.exists():
        audit_path.unlink()
    set_config({}, actor="test-fixture", replace=True)
    if audit_path.exists():
        audit_path.unlink()
    with TestClient(create_app()) as client:
        try:
            yield client, token
        finally:
            set_config({}, actor="test-fixture", replace=True)
            reset_config()
            if audit_path.exists():
                audit_path.unlink()


def test_history_rollback_restores_previous_state(admin_history_client) -> None:
    client, token = admin_history_client
    headers = {"Authorization": f"Bearer {token}"}

    baseline = get_config()
    set_config({"shadow_enable": True, "shadow_timeout_ms": 250}, actor="tester-change")
    assert get_config()["shadow_enable"] is True

    versions = client.get("/admin/config/versions?limit=5", headers=headers)
    assert versions.status_code == 200
    ts = versions.json()[0]["ts"]

    page = client.get("/admin/ui/config/history", headers=headers)
    assert page.status_code == 200
    csrf_token = client.cookies.get("ui_csrf")
    assert csrf_token

    resp = client.post(
        "/admin/config/rollback",
        headers=headers,
        json={"ts": ts, "csrf_token": csrf_token},
    )
    assert resp.status_code == 200

    rolled = get_config()
    assert rolled["shadow_enable"] == baseline["shadow_enable"]
    assert rolled["shadow_timeout_ms"] == baseline["shadow_timeout_ms"]


def test_history_rollback_requires_csrf(admin_history_client) -> None:
    client, token = admin_history_client
    headers = {"Authorization": f"Bearer {token}"}

    set_config({"shadow_enable": True}, actor="tester-change")
    versions = client.get("/admin/config/versions?limit=5", headers=headers)
    assert versions.status_code == 200
    ts = versions.json()[0]["ts"]

    resp = client.post("/admin/config/rollback", headers=headers, json={"ts": ts})
    assert resp.status_code == 400
    body = resp.json()
    assert body.get("detail") == "CSRF failed"

    assert get_config()["shadow_enable"] is True
