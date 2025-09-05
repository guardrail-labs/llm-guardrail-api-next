from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main


def test_openai_streaming_sse() -> None:
    payload = {
        "model": "demo",
        "stream": True,
        "messages": [{"role": "user", "content": "please reply"}],
    }
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Accept": "text/event-stream",
    }

    # Use the app directly — no custom ASGI shim.
    with TestClient(main.app) as client:
        resp = client.post("/v1/chat/completions", headers=headers, json=payload)

    assert resp.status_code == 200

    body = resp.text
    resp_headers = dict(resp.headers)

    # SSE payload assertions
    assert "data: [DONE]" in body
    assert "[REDACTED:EMAIL]" in body

    # Guardrail headers
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
