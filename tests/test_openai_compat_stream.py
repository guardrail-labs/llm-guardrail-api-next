from __future__ import annotations

import asyncio
import httpx

# Your FastAPI ASGI app should be exposed as `app` here
import app.main as main


def test_openai_streaming_sse():
    """
    Validate SSE streaming for OpenAI-compatible /v1/chat/completions.

    Runs an async client inside asyncio.run(), so we don't need pytest-asyncio.
    Uses ASGITransport to support the httpx version in CI (no AsyncClient(app=...)).
    """

    async def _run():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {
                "X-API-Key": "k",
                "X-Tenant-ID": "acme",
                "X-Bot-ID": "assistant-1",
                "Content-Type": "application/json",
            }
            payload = {
                "model": "demo",
                "stream": True,
                "messages": [{"role": "user", "content": "please reply"}],
            }

            # Stream the SSE response
            async with ac.stream(
                "POST",
                "/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=5.0,
            ) as r:
                assert r.status_code == 200
                buf = ""
                async for chunk in r.aiter_text():
                    if chunk:
                        buf += chunk
                # Capture headers before context closes
                resp_headers = dict(r.headers)

        # Basic SSE terminator and redaction checks
        assert "data: [DONE]" in buf
        assert "[REDACTED:EMAIL]" in buf

        # Guardrail headers present and sensible
        assert resp_headers.get("X-Guardrail-Policy-Version") is not None
        assert resp_headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
        assert resp_headers.get("X-Guardrail-Egress-Action") == "allow"

    asyncio.run(_run())
