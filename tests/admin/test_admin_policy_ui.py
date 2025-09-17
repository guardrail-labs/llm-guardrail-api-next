from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("ADMIN_UI_TOKEN", "secret")
    return TestClient(create_app())


def test_policy_page_renders(monkeypatch):
    c = _client(monkeypatch)
    r = c.get("/admin/policy", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    html = r.text
    assert "Active Version" in html
