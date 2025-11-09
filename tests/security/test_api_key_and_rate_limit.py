# tests/security/test_api_key_and_rate_limit.py
# Summary (PR-J test fix 2):
# - Remove unused type: ignore comments to satisfy mypy.
# - Reload app.main after setting env so install_security runs with fresh config.

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client_with_env(monkeypatch, env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_api_key_required_on_secured_path(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "API_SECURITY_ENABLED": "1",
            "GUARDRAIL_API_KEYS": "k1",
            "SECURED_PATH_PREFIXES": "/admin",
            "RATE_LIMIT_RPS": "100",
            "RATE_LIMIT_BURST": "100",
        },
    )

    # Missing key -> 401
    r = client.get("/admin")
    assert r.status_code == 401

    # Wrong key -> 401
    r = client.get("/admin", headers={"x-api-key": "nope"})
    assert r.status_code == 401

    # Correct key -> 200
    r = client.get("/admin", headers={"x-api-key": "k1"})
    assert r.status_code == 200


def test_rate_limit_applies_per_key(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "API_SECURITY_ENABLED": "1",
            "GUARDRAIL_API_KEYS": "k1,k2",
            "SECURED_PATH_PREFIXES": "/admin",
            "RATE_LIMIT_RPS": "2",
            "RATE_LIMIT_BURST": "2",
        },
    )

    h1 = {"x-api-key": "k1"}
    # First two pass (use burst capacity)
    assert client.get("/admin", headers=h1).status_code == 200
    assert client.get("/admin", headers=h1).status_code == 200
    # Third should be limited
    r3 = client.get("/admin", headers=h1)
    assert r3.status_code == 429

    # Different key should have its own bucket and pass
    h2 = {"x-api-key": "k2"}
    r_other = client.get("/admin", headers=h2)
    assert r_other.status_code == 200
