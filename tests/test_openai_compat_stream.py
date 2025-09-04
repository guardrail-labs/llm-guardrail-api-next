from __future__ import annotations
from typing import Any
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send, Message

import app.main as main


class _DisconnectAfterResponseStart:
    """
    ASGI shim for tests:

    - Before the response starts: pass through messages unchanged.
    - After we see `http.response.start`: every `receive()` returns `http.disconnect`.

    This avoids BaseHTTPMiddleware raising:
    "Unexpected message received: http.request" while StreamingResponse
    listens for disconnects during SSE.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def patched_receive() -> Message:
            # After the response has started, only ever surface a disconnect
            if response_started:
                return {"type": "http.disconnect"}
            return await receive()

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

    with TestClient(_DisconnectAfterResponseStart(main.app)) as client:
        resp = client.post("/v1/chat/completions", headers=headers, json=payload)
        assert resp.status_code == 200

        buf = resp.text
        resp_headers = dict(resp.headers)

    assert "data: [DONE]" in buf
    assert "[REDACTED:EMAIL]" in buf
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
