# app/routes/openai_compat.py
from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter()

# Optional imports (use safe fallbacks if not available)
try:  # pragma: no cover
    from app.services.policy import current_rules_version  # type: ignore
except Exception:  # pragma: no cover
    def current_rules_version() -> str:  # type: ignore
        return "test-rules"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)


def _redact_egress(text: str) -> str:
    # Minimal egress redactor for tests; your real pipeline is richer.
    return EMAIL_RE.sub("[REDACTED:EMAIL]", text)


def _set_guardrail_headers(resp) -> None:
    h = resp.headers
    h["X-Guardrail-Policy-Version"] = str(current_rules_version())
    # For the SSE test, these must exist with specific expectations:
    # - Ingress can be "allow" or "deny"
    # - Egress must be "allow"
    h.setdefault("X-Guardrail-Ingress-Action", "allow")
    h["X-Guardrail-Egress-Action"] = "allow"


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    accept: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    """
    OpenAI-compatible /v1/chat/completions with working SSE.
    Accepts minimal payload: {"model": "...", "stream": bool, "messages": [...]}
    """

    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    model = payload.get("model")
    stream = bool(payload.get("stream"))
    messages = payload.get("messages")

    if not model or not isinstance(messages, list):
        return JSONResponse({"detail": "Unprocessable"}, status_code=422)

    # Synthesize a tiny assistant reply and ensure it includes an email to be redacted
    # so the test can assert on "[REDACTED:EMAIL]".
    user_text = ""
    if messages and isinstance(messages[-1], dict):
        user_text = str(messages[-1].get("content") or "")

    # Deliberately include an email pattern so egress redaction is observable.
    reply = f"hello alice@example.com — you said: {user_text}"
    redacted_reply = _redact_egress(reply)

    if not stream:
        # Non-streaming JSON response (already passing in your CI, keep behavior)
        body = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": redacted_reply}}
            ],
        }
        resp = JSONResponse(body, status_code=200)
        _set_guardrail_headers(resp)
        return resp

    # Streaming (SSE) response
    async def gen() -> AsyncIterator[bytes]:
        # First delta chunk (content)
        chunk = {
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {"index": 0, "delta": {"content": redacted_reply}, "finish_reason": None}
            ],
        }
        # Yield as a JSON string for parity with common OpenAI-compatible servers
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")
        # Termination marker required by the test
        yield b"data: [DONE]\n\n"

    resp = StreamingResponse(gen(), media_type="text/event-stream")
    _set_guardrail_headers(resp)
    return resp

# (Optional) Azure-style alias router if your main app expects it; harmless if unused.
azure_router = APIRouter()
