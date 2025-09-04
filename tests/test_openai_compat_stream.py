from __future__ import annotations

import asyncio
import json
import httpx

# Your FastAPI ASGI app should be exposed as `app` here
import app.main as main


def test_openai_streaming_sse():
    """
    Validate SSE streaming for OpenAI-compatible /v1/chat/completions.

    Runs an async client inside asyncio.run() (no pytest-asyncio).
    Uses ASGITransport and sends a single-shot body via `content=...`
    to avoid extra `http.request` frames that upset Starlette middleware.
    """

   async def _run():
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
            "Content-Length": str(len(body_bytes)),  # <-- force single-frame body
        }

        async with ac.stream(
            "POST",
            "/v1/chat/completions",
            headers=headers,
            content=body_bytes,   # <-- send bytes, not str, not json=
            timeout=10.0,
        ) as r:
            assert r.status_code == 200
            buf = ""
            async for chunk in r.aiter_text():
                if chunk:
                    buf += chunk
            resp_headers = dict(r.headers)

    assert "data: [DONE]" in buf
    assert "[REDACTED:EMAIL]" in buf
    assert resp_headers.get("X-Guardrail-Policy-Version") is not None
    assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
    assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"
    asyncio.run(_run())
