from __future__ import annotations

import importlib
from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient


class FakeClient:
    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        # Return something that triggers egress redaction (email).
        return "Hi user@example.com", {"provider": "fake", "model": model}


def _client(monkeypatch):
    # Wire fake provider
    import app.routes.proxy as proxy

    monkeypatch.setattr(proxy, "get_client", lambda: FakeClient())

    # Fresh app for clean metrics
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    import app.main as main

    importlib.reload(main)
    return TestClient(main.app)


def test_proxy_chat_flow(monkeypatch):
    c = _client(monkeypatch)
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Content-Type": "application/json",
    }

    r = c.post(
        "/proxy/chat",
        json={
            "model": "demo",
            "messages": [{"role": "user", "content": "hello world"}],
        },
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()

    # presence
    assert "request_id" in data and data["request_id"]
    assert data["policy_version"]
    assert data["model"]["provider"] in ("fake", "local-echo")

    # ingress
    ing = data["ingress"]
    assert ing["action"] in ("allow", "deny")
    assert "transformed_text" in ing

    # egress: email should be redacted
    out_txt = data["output_text"]
    assert "[REDACTED:EMAIL]" in out_txt
    eg = data["egress"]
    assert eg["action"] == "allow"
    assert eg["redactions"] >= 1
