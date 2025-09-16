from __future__ import annotations

from pathlib import Path
from typing import Iterator, List

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.config_store import reset_config, set_config


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


def test_history_list_returns_recent_entries(admin_history_client) -> None:
    client, token = admin_history_client
    headers = {"Authorization": f"Bearer {token}"}

    set_config({"shadow_enable": True}, actor="tester-1")
    set_config({"shadow_sample_rate": 0.25}, actor="tester-2")

    resp = client.get("/admin/config/versions?limit=10", headers=headers)
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload, list)
    assert len(payload) >= 2

    entries: List[dict] = payload
    first, second = entries[0], entries[1]
    assert first.get("actor") == "tester-2"
    assert "shadow_sample_rate" in first.get("changed_keys", [])
    assert "shadow_enable" in second.get("changed_keys", [])
    ts_first = first.get("ts")
    ts_second = second.get("ts")
    assert isinstance(ts_first, int)
    assert isinstance(ts_second, int)
    assert ts_first >= ts_second
    assert all(isinstance(item.get("changed_keys", []), list) for item in entries)
