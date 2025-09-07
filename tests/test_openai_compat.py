from __future__ import annotations

import importlib
from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient


class FakeClient:
    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        # Return a string that triggers egress redaction (email).
        return "Hello user@example.com", {"provider": "fake", "model": model}


def _client(monkeypatch):
    # Wire fake provider
    import app.routes.openai_compat as compat

    monkeypatch.setattr(compat, "get_client", lambda: FakeClient())

    # Fresh app so routers and metrics are clean
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_openai_chat_compat(monkeypatch):
    c = _client(monkeypatch)
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Content-Type": "application/json",
    }

    r = c.post(
        "/v1/chat/completions",
        json={
            "model": "demo",
            "messages": [{"role": "user", "content": "hey there"}],
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["object"] == "chat.completion"
    assert "choices" in data and data["choices"]
    out = data["choices"][0]["message"]["content"]
    # email should be redacted by egress
    assert "[REDACTED:EMAIL]" in out

    # guard headers present
    assert r.headers.get("X-Guardrail-Policy-Version")
    assert r.headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert r.headers.get("X-Guardrail-Egress-Action") == "allow"
