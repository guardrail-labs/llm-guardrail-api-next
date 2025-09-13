# tests/routes/test_well_known.py
# Summary: Sanity checks for robots.txt and security.txt.

from __future__ import annotations

from starlette.testclient import TestClient

import app.main as main


def test_robots_txt_defaults_disallow_admin(monkeypatch) -> None:
    # Clear custom env to test defaults
    monkeypatch.delenv("ROBOTS_ALLOW", raising=False)
    monkeypatch.delenv("ROBOTS_DISALLOW", raising=False)

    client = TestClient(main.app)
    r = client.get("/robots.txt")
    assert r.status_code == 200
    text = r.text
    assert "User-agent: *" in text
    assert "Disallow: /admin" in text


def test_security_txt_served_when_contact_set(monkeypatch) -> None:
    client = TestClient(main.app)

    # Absent -> 404
    monkeypatch.delenv("SECURITY_CONTACT", raising=False)
    r1 = client.get("/.well-known/security.txt")
    assert r1.status_code == 404

    # Present -> 200 and includes fields
    monkeypatch.setenv("SECURITY_CONTACT", "mailto:security@example.com")
    monkeypatch.setenv("SECURITY_POLICY", "https://example.com/security-policy")
    r2 = client.get("/.well-known/security.txt")
    assert r2.status_code == 200
    assert "[REDACTED-EMAIL]" in r2.text
    assert "Policy: https://example.com/security-policy" in r2.text
