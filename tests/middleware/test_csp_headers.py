# tests/middleware/test_csp_headers.py
# Summary: CSP/Referrer-Policy headers appear only when enabled.

from __future__ import annotations

from starlette.testclient import TestClient

import app.main as main


def test_csp_headers_disabled_by_default(monkeypatch) -> None:
    # Ensure env is unset (use delenv; avoid dict with None to satisfy mypy)
    monkeypatch.delenv("CSP_ENABLED", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_ENABLED", raising=False)
    monkeypatch.delenv("CSP_VALUE", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_VALUE", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("content-security-policy") is None
    assert h.get("referrer-policy") is None


def test_csp_and_referrer_enabled_with_defaults(monkeypatch) -> None:
    monkeypatch.setenv("CSP_ENABLED", "1")
    monkeypatch.setenv("REFERRER_POLICY_ENABLED", "1")
    # Clear custom values to use defaults
    monkeypatch.delenv("CSP_VALUE", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_VALUE", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("content-security-policy") == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    assert h.get("referrer-policy") == "no-referrer"


def test_csp_custom_values(monkeypatch) -> None:
    monkeypatch.setenv("CSP_ENABLED", "1")
    monkeypatch.setenv("CSP_VALUE", "default-src 'self'")
    # Referrer remains disabled unless toggled
    monkeypatch.delenv("REFERRER_POLICY_ENABLED", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("content-security-policy") == "default-src 'self'"
