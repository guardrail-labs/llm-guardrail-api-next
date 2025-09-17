from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_get_policy_version_ok():
    c = _client()
    r = c.get("/admin/api/policy/version")
    assert r.status_code == 200
    j = r.json()
    assert "version" in j and isinstance(j["version"], str)
    assert "packs" in j and isinstance(j["packs"], list)


def test_policy_reload_requires_csrf():
    c = _client()
    # Missing CSRF → 400
    r = c.post("/admin/api/policy/reload", json={})
    assert r.status_code == 400


def test_policy_reload_with_double_submit_csrf():
    c = _client()
    token = "testtoken123"
    # Cookie + matching body token
    r = c.post(
        "/admin/api/policy/reload",
        cookies={"ui_csrf": token},
        json={"csrf_token": token},
    )
    assert r.status_code == 200
    j = r.json()
    assert "version" in j and isinstance(j["version"], str)
    assert len(j["version"]) == 64  # sha256 hex
