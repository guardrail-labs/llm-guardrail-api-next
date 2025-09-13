# tests/middleware/test_csp_headers.py
# Summary: Validate CSP middleware behavior while coexisting with default
# security headers (which always emit Referrer-Policy by default).

from __future__ import annotations

from starlette.testclient import TestClient

import app.main as main


def test_csp_headers_disabled_by_default(monkeypatch) -> None:
    # Ensure CSP module is disabled; security headers may still add Referrer-Policy
    monkeypatch.delenv("CSP_ENABLED", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_ENABLED", raising=False)
    monkeypatch.delenv("CSP_VALUE", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_VALUE", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    # CSP header should not be present unless CSP_ENABLED=1
    assert h.get("content-security-policy") is None
    # Referrer-Policy is provided by the security_headers middleware by default
    assert h.get("referrer-policy") == "no-referrer"


def test_csp_and_referrer_enabled_with_defaults(monkeypatch) -> None:
    # Enable CSP middleware (and its own referrer if toggled)
    monkeypatch.setenv("CSP_ENABLED", "1")
    monkeypatch.setenv("REFERRER_POLICY_ENABLED", "1")
    # Clear custom values to use defaults
    monkeypatch.delenv("CSP_VALUE", raising=False)
    monkeypatch.delenv("REFERRER_POLICY_VALUE", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    # CSP header should appear with default policy
    assert h.get("content-security-policy") == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    # Referrer-Policy remains "no-referrer" (CSP or security headers both agree)
    assert h.get("referrer-policy") == "no-referrer"


def test_csp_custom_values(monkeypatch) -> None:
    # Custom CSP value
    monkeypatch.setenv("CSP_ENABLED", "1")
    monkeypatch.setenv("CSP_VALUE", "default-src 'self'")
    # CSP module's own referrer toggle left off; security headers still emit default
    monkeypatch.delenv("REFERRER_POLICY_ENABLED", raising=False)

    client = TestClient(main.app)
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("content-security-policy") == "default-src 'self'"
    # Sanity: referrer-policy present from security headers
    assert h.get("referrer-policy") == "no-referrer"
