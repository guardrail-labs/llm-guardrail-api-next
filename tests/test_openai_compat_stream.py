from __future__ import annotations
from typing import Any
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send, Message

import app.main as main


class _AfterEOFAndAfterStartOnlyDisconnect:
    """
    Test-only ASGI shim:

    - Before the request body EOF and before response start: pass through.
    - After we observe request EOF (`http.request` with `more_body` false),
      *or* after we see `http.response.start`, every subsequent `receive()`
      returns `http.disconnect`.

    This keeps Starlette's BaseHTTPMiddleware happy during StreamingResponse/SSE.
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
        nonlocal eof_seen
        nonlocal response_started
        if eof_seen or response_started:
            return {"type": "http.disconnect"}
        msg = await receive()
        if msg.get("type") == "http.request":
            if not msg.get("more_body", False):
                eof_seen = True
        # Gracefully ignore unexpected additional http.request messages.
        if response_started:
            return {"type": "http.disconnect"}
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

    with TestClient(_AfterEOFAndAfterStartOnlyDisconnect(main.app)) as client:
        resp = client.post("/v1/chat/completions", headers=headers, json=payload)
        assert resp.status_code == 200

        buf = resp.text
        resp_headers = dict(resp.headers)

    assert "data: [DONE]" in buf
    assert "[REDACTED:EMAIL]" in buf
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
