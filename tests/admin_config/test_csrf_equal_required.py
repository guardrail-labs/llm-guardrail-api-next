from __future__ import annotations

import os
from typing import Optional

from starlette.testclient import TestClient


def _client() -> TestClient:
    os.environ["ADMIN_UI_TOKEN"] = "secret"
    from app.app import create_app

    app = create_app()
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


def test_csrf_mismatch_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    c = _client()
    r_ui = c.get("/admin/ui", headers=_auth())
    assert r_ui.status_code == 200
    cookie_token: Optional[str] = c.cookies.get("ui_csrf")
    assert cookie_token
    r_bad = c.post(
        "/admin/config",
        headers=_auth(),
        data={"csrf_token": "not-the-cookie", "lock_enable": "true"},
    )
    assert r_bad.status_code == 400
    assert r_bad.json()["detail"] == "CSRF failed"


def test_csrf_equal_allows_update(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    c = _client()
    r_ui = c.get("/admin/ui", headers=_auth())
    assert r_ui.status_code == 200
    cookie_token = c.cookies.get("ui_csrf")
    assert cookie_token
    r_ok = c.post(
        "/admin/config",
        headers=_auth(),
        data={"csrf_token": cookie_token, "lock_enable": "true"},
    )
    assert r_ok.status_code == 200
    assert r_ok.json()["lock_enable"] is True
