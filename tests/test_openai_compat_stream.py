from __future__ import annotations

from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send, Message

import app.main as main


class _DisconnectAfterEOFOrStart:
    """
    Test-only ASGI shim.

    - Before request EOF and before response start: pass through.
    - After we observe request EOF (http.request with more_body False) OR
      after we see http.response.start, every subsequent receive() returns
      http.disconnect. This keeps Starlette's BaseHTTPMiddleware happy
      during StreamingResponse/SSE.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        eof_seen = False
        response_started = False

        async def patched_receive() -> Message:
            nonlocal eof_seen, response_started
            # After EOF or once the response has started, always signal disconnect.
            if eof_seen or response_started:
                return {"type": "http.disconnect"}

            msg = await receive()
            if msg.get("type") == "http.request" and not msg.get("more_body", False):
                eof_seen = True
            return msg

        async def patched_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, patched_receive, patched_send)


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

    # Wrap the app with the shim so downstream middlewares never see stray http.request
    with TestClient(_DisconnectAfterEOFOrStart(main.app)) as client:
        resp = client.post("/v1/chat/completions", headers=headers, json=payload)

    assert resp.status_code == 200

    body = resp.text
    resp_headers = dict(resp.headers)

    assert "data: [DONE]" in body
    assert "[REDACTED:EMAIL]" in body
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
