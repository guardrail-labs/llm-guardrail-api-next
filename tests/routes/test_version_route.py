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
    assert "info" in data and "config" in data
    assert data["info"]["version"] == "9.9.9"
    assert data["info"]["commit"] == "abc123"
    assert "verifier_sampling_pct" in data["config"]
