# tests/middleware/test_cors_and_security_headers.py
# Summary (PR-K): Validates CORS preflight/allow headers and security headers.
# - Uses env + reload(app.main) pattern so middleware attaches at startup.

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client_with_env(monkeypatch, env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_cors_preflight_and_allow_header(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "CORS_ENABLED": "1",
            "CORS_ALLOW_ORIGINS": "http://example.com",
            "CORS_ALLOW_METHODS": "GET,POST,OPTIONS",
            "CORS_ALLOW_HEADERS": "Content-Type,X-API-KEY",
            "CORS_MAX_AGE": "600",
        },
    )

    # Preflight
    r_pre = client.options(
        "/admin",
        headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r_pre.status_code in (200, 204)
    assert r_pre.headers.get("access-control-allow-origin") == "http://example.com"
    assert "GET" in (r_pre.headers.get("access-control-allow-methods") or "")

    # Actual request includes ACAO
    r_get = client.get("/admin", headers={"Origin": "http://example.com"})
    assert r_get.status_code in (200, 401, 307, 302)  # UI or security could be enabled elsewhere
    assert r_get.headers.get("access-control-allow-origin") == "http://example.com"


def test_security_headers(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "SEC_HEADERS_ENABLED": "1",
            "SEC_HEADERS_FRAME_DENY": "1",
            "SEC_HEADERS_CONTENT_TYPE_NOSNIFF": "1",
            "SEC_HEADERS_REFERRER_POLICY": "no-referrer",
            "SEC_HEADERS_PERMISSIONS_POLICY": "geolocation=()",
            # Leave HSTS off to avoid coupling to HTTPS-only expectations in tests
            "SEC_HEADERS_HSTS": "0",
        },
    )

    r = client.get("/admin")
    assert r.status_code in (200, 401, 307, 302)
    h = r.headers
    assert h.get("x-frame-options") == "DENY"
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("referrer-policy") == "no-referrer"
    assert "Permissions-Policy" in h or "permissions-policy" in {k.lower() for k in h.keys()}
