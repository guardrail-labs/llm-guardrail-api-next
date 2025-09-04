from __future__ import annotations

import asyncio
import json

import httpx

# Your FastAPI ASGI app should be exposed as `app` here
import app.main as main


def test_openai_streaming_sse() -> None:
    """
    Validate SSE behavior for OpenAI-compatible /v1/chat/completions.

    We intentionally avoid client-side streaming (.stream context) because some
    Starlette BaseHTTPMiddleware variants raise "Unexpected message received:
    http.request" when the transport delivers trailing request frames during a
    streaming response. Here, we send the full request up front and read the
    entire SSE payload after the server closes the stream.
    """

    async def _run() -> None:
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            payload = {
                "model": "demo",
                "stream": True,
                "messages": [{"role": "user", "content": "please reply"}],
            }
            body_bytes = json.dumps(payload).encode("utf-8")

            headers = {
                "X-API-Key": "k",
                "X-Tenant-ID": "acme",
                "X-Bot-ID": "assistant-1",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "Content-Length": str(len(body_bytes)),  # send as a single body
            }

            # Send request normally (no streaming context) and read full SSE text.
            r = await ac.post(
                "/v1/chat/completions",
                headers=headers,
                content=body_bytes,  # don't use json= to avoid chunking
                timeout=15.0,
            )

            assert r.status_code == 200
            buf = r.text
            resp_headers = dict(r.headers)

        # Basic SSE terminator and redaction checks
        assert "data: [DONE]" in buf
        assert "[REDACTED:EMAIL]" in buf

        # Guardrail headers present and sensible
        assert resp_headers.get("X-Guardrail-Policy-Version") is not None
        assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
        assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"

    asyncio.run(_run())
