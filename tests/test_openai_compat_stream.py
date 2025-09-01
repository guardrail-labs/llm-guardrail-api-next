from __future__ import annotations

import importlib
from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient


class FakeClient:
    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        # Include an email so egress redacts it before streaming.
        return "Hello user@example.com — welcome!", {"provider": "fake", "model": model}


def _client(monkeypatch):
    import app.routes.openai_compat as compat
    monkeypatch.setattr(compat, "get_client", lambda: FakeClient())

    import app.telemetry.metrics as metrics
    importlib.reload(metrics)
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_openai_streaming_sse(monkeypatch):
    c = _client(monkeypatch)
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Content-Type": "application/json",
    }

    with c.stream(
        "POST",
        "/v1/chat/completions",
        headers=headers,
        json={
            "model": "demo",
            "stream": True,
            "messages": [{"role": "user", "content": "please reply"}],
        },
        timeout=5.0,
    ) as r:
        assert r.status_code == 200
        buf = ""
        for chunk in r.iter_text():
            buf += chunk or ""
        # Final terminator
        assert "data: [DONE]" in buf
        # Redaction should appear in at least one chunk
        assert "[REDACTED:EMAIL]" in buf
        # Guard headers should be present
        assert r.headers.get("X-Guardrail-Policy-Version")
        assert r.headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
        assert r.headers.get("X-Guardrail-Egress-Action") == "allow"
