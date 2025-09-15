from __future__ import annotations

from importlib import reload

from starlette.testclient import TestClient


def _make_client(monkeypatch, tmp_path) -> TestClient:
    cfg_path = tmp_path / "cfg.json"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CONFIG_PATH", str(cfg_path))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(audit_path))
    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")

    from app.services import config_store as cs
    from app.services import enforcement as enforcement_mod
    from app.services import escalation as escalation_mod

    reload(cs)
    reload(enforcement_mod)
    reload(escalation_mod)

    from app.main import create_app

    return TestClient(create_app())


def test_get_post_config_roundtrip(tmp_path, monkeypatch) -> None:
    client = _make_client(monkeypatch, tmp_path)

    assert client.get("/admin/config").status_code == 401

    resp_ui = client.get("/admin/ui", headers={"Authorization": "Bearer secret"})
    assert resp_ui.status_code == 200
    csrf = client.cookies.get("ui_csrf")
    assert csrf

    resp = client.post(
        "/admin/config",
        headers={"Authorization": "Bearer secret"},
        data={
            "csrf_token": csrf,
            "lock_enable": "true",
            "escalation_deny_threshold": "4",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["lock_enable"] is True
    assert body["escalation_deny_threshold"] == 4

    fetched = client.get("/admin/config", headers={"Authorization": "Bearer secret"})
    assert fetched.status_code == 200
    data = fetched.json()
    assert data["lock_enable"] is True
    assert data["escalation_deny_threshold"] == 4
