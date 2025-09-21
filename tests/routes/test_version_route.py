# tests/routes/test_version_route.py
# Summary: Basic sanity checks for /version endpoint (no async plugin needed).

from __future__ import annotations

from starlette.testclient import TestClient

import app.main as main


def test_version_endpoint_includes_info_and_config(monkeypatch) -> None:
    client = TestClient(main.app)
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    monkeypatch.setenv("GIT_SHA", "abc123")
    r = client.get("/version")
    assert r.status_code == 200
    data = r.json()
    assert data["version"] == "9.9.9"
    assert data["git_sha"] == "abc123"
    assert "runtime" in data and isinstance(data["runtime"], dict)
    assert data["features"]["admin_auth_mode"] == "cookie"
