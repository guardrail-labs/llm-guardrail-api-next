# tests/middleware/test_csp_headers.py
# Summary: CSP/Referrer-Policy headers appear only when enabled.

from __future__ import annotations

import importlib

from starlette.testclient import TestClient


def _client_with_env(monkeypatch, env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_csp_headers_disabled_by_default(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "CSP_ENABLED": None,
            "REFERRER_POLICY_ENABLED": None,
        },
    )
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("content-security-policy") is None
    assert h.get("referrer-policy") is None


def test_csp_and_referrer_enabled_with_defaults(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "CSP_ENABLED": "1",
            "REFERRER_POLICY_ENABLED": "1",
        },
    )
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("content-security-policy") == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    assert h.get("referrer-policy") == "no-referrer"


def test_csp_custom_values(monkeypatch) -> None:
    client = _client_with_env(
        monkeypatch,
        {
            "CSP_ENABLED": "1",
            "CSP_VALUE": "default-src 'self'",
        },
    )
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("content-security-policy") == "default-src 'self'"
