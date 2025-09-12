# tests/security/test_api_key_and_rate_limit.py
# Summary (PR-J): Opt-in auth + rate limit tests using existing /admin UI as target path.
# - We explicitly secure "/admin" via SECURED_PATH_PREFIXES for these tests only.

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import install_security

client = TestClient(app)


def test_api_key_required_on_secured_path(monkeypatch) -> None:
    # Enable security and secure /admin paths for this test only
    monkeypatch.setenv("API_SECURITY_ENABLED", "1")
    monkeypatch.setenv("GUARDRAIL_API_KEYS", "k1")
    monkeypatch.setenv("SECURED_PATH_PREFIXES", "/admin")
    # Ensure generous rate limits so this test focuses on auth
    monkeypatch.setenv("RATE_LIMIT_RPS", "100")
    monkeypatch.setenv("RATE_LIMIT_BURST", "100")
    # (Re)install middlewares with current env
    install_security(app)

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
    monkeypatch.setenv("API_SECURITY_ENABLED", "1")
    monkeypatch.setenv("GUARDRAIL_API_KEYS", "k1,k2")
    monkeypatch.setenv("SECURED_PATH_PREFIXES", "/admin")
    # Tight limit: 2 req/s with burst 2, so third immediate call should 429
    monkeypatch.setenv("RATE_LIMIT_RPS", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")
    install_security(app)

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
