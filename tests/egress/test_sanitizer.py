from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app.main import create_app


def _client():
    return TestClient(create_app())

def test_sanitize_sets_headers_and_metrics():
    c = _client()

    payload = {
        "text": "Contact me at foo@example.com. SECRET token here.",
        "tenant": "acme",
        "bot": "chatbot-a",
    }
    r = c.post("/guardrail/sanitize", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["redactions"] >= 2
    assert "[REDACTED]" in data["text"]

    h = r.headers
    assert h.get("X-Guardrail-Decision") == "allow"
    assert h.get("X-Guardrail-Egress-Action") == "redact"
    assert h.get("X-Guardrail-Redactions") is not None

    # metrics should reflect increments per reason
    m = c.get("/metrics").text
    assert re.search(
        r'guardrail_egress_redactions_total\{[^}]*bot="chatbot-a"[^}]*reason="email"[^}]*tenant="acme"',
        m,
    )
    assert re.search(
        r'guardrail_egress_redactions_total\{[^}]*bot="chatbot-a"[^}]*reason="secret"[^}]*tenant="acme"',
        m,
    )
