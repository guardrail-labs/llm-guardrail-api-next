from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Your FastAPI app
import app.main as main


class _AfterBodyRequestBecomesDisconnect:
    """
    ASGI test shim:
    - For HTTP scopes, once we see a request frame with `more_body=False`
      (end-of-body), any subsequent `http.request` frames are converted
      to `http.disconnect`.
    - This works around BaseHTTPMiddleware raising
      "Unexpected message received: http.request" while a StreamingResponse
      listens for disconnects.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        seen_eof = False

        async def patched_receive() -> Message:
            nonlocal seen_eof
            msg: Message = await receive()

            if msg.get("type") == "http.request":
                # Mark EOF when more_body=False (end of body)
                if not msg.get("more_body", False):
                    if seen_eof:
                        # Any further http.request after EOF -> disconnect
                        return {"type": "http.disconnect"}  # type: ignore[return-value]
                    seen_eof = True
                return msg  # type: ignore[return-value]

            # Pass through anything else (e.g., http.disconnect)
            return msg  # type: ignore[return-value]

        await self.app(scope, patched_receive, send)


def test_openai_streaming_sse() -> None:
    """
    Validate SSE behavior for OpenAI-compatible /v1/chat/completions.

    We wrap the app with a small ASGI shim that converts any stray
    post-EOF `http.request` frames to `http.disconnect`, avoiding
    Starlette BaseHTTPMiddleware's strict check during streaming.
    """

    payload = {
        "model": "demo",
        "stream": True,
        "messages": [{"role": "user", "content": "please reply"}],
    }

    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        # We expect an SSE response:
        "Accept": "text/event-stream",
    }

    with TestClient(_AfterBodyRequestBecomesDisconnect(main.app)) as client:
        resp = client.post("/v1/chat/completions", headers=headers, json=payload)

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
