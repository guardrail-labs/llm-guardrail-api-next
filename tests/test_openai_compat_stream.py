from __future__ import annotations

import json

from fastapi.testclient import TestClient

# Your FastAPI ASGI app should be exposed as `app` here
import app.main as main


def test_openai_streaming_sse() -> None:
    """
    Validate SSE behavior for OpenAI-compatible /v1/chat/completions.

    We use FastAPI's sync TestClient to avoid Event Loop/plugin dependencies
    and to sidestep Starlette BaseHTTPMiddleware issues that can appear when
    exercising client-side streaming with ASGI transports.
    """

    payload = {
        "model": "demo",
        "stream": True,
        "messages": [{"role": "user", "content": "please reply"}],
    }

    # Build headers typical for the gateway
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    with TestClient(main.app) as client:
        # Send JSON body in one shot; TestClient ensures a single, complete request
        resp = client.post(
            "/v1/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=15,
        )

        assert resp.status_code == 200

        buf = resp.text
        resp_headers = dict(resp.headers)

    # Basic SSE terminator and redaction checks
    assert "data: [DONE]" in buf
    assert "[REDACTED:EMAIL]" in buf

    # Guardrail headers present and sensible
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
