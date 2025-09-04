from __future__ import annotations

import pytest
import httpx

# We assume your FastAPI app is exposed as `app` in app.main
# (this matches how other tests import the ASGI app)
import app.main as main


@pytest.mark.asyncio
async def test_openai_streaming_sse(monkeypatch):
    """
    Validate SSE streaming for OpenAI-compatible /v1/chat/completions.

    Uses httpx.AsyncClient to avoid Starlette TestClient streaming quirks
    that surface as "Unexpected message received: http.request".
    """
    # Async ASGI client
    async with httpx.AsyncClient(app=main.app, base_url="http://test") as ac:
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
            # Accumulate the SSE text stream
            buf = ""
            async for chunk in r.aiter_text():
                if chunk:
                    buf += chunk

        # Basic SSE terminator and redaction checks
        assert "data: [DONE]" in buf
        assert "[REDACTED:EMAIL]" in buf

        # Guardrail headers present and sensible
        # (names match the rest of the suite)
        # Note: depending on policy, ingress action may be "allow" or "deny"
        # Egress should be "allow" for benign demo responses.
        # If your implementation differs, adjust expected values accordingly.
        # These headers should be on the *final* response object (`r`).
        assert r.headers.get("X-Guardrail-Policy-Version") is not None
        assert r.headers.get("X-Guardrail-Ingress-Action") in ("allow", "deny")
        assert r.headers.get("X-Guardrail-Egress-Action") == "allow"
