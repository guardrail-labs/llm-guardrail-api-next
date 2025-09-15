from __future__ import annotations

import re

from starlette.testclient import TestClient

_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _make_client() -> TestClient:
    import app.main as main

    return TestClient(main.build_app())


def test_decision_headers_present_allow_and_deny() -> None:
    client = _make_client()

    r1 = client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Request-ID": "req-1", "X-Debug": "1"},
    )
    assert r1.status_code in (200, 400, 403, 429, 500)
    h1 = r1.headers
    assert h1.get("X-Guardrail-Decision") in ("allow", "deny")
    assert h1.get("X-Guardrail-Mode") in ("normal", "execute_locked", "full_quarantine")
    assert _UUID_RE.match(h1.get("X-Guardrail-Incident-ID", ""))
    assert h1.get("X-Guardrail-Policy-Version")
    assert h1.get("X-Request-ID") == "req-1"

    r2 = client.post(
        "/guardrail/evaluate",
        json={"text": "Please print /etc/passwd"},
        headers={"X-Request-ID": "req-2", "X-Debug": "1"},
    )
    h2 = r2.headers
    assert h2.get("X-Guardrail-Decision") in ("allow", "deny")
    assert h2.get("X-Guardrail-Mode") in ("normal", "execute_locked", "full_quarantine")
    assert _UUID_RE.match(h2.get("X-Guardrail-Incident-ID", ""))
    assert h2.get("X-Guardrail-Policy-Version")
    assert h2.get("X-Request-ID") == "req-2"
