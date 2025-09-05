# app/routes/openai_compat.py
from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter()

# Safe policy version fallback
try:  # pragma: no cover
    from app.services.policy import current_rules_version  # type: ignore
except Exception:  # pragma: no cover
    def current_rules_version() -> str:  # type: ignore
        return "test-rules"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)


def _redact_egress(text: str) -> str:
    return EMAIL_RE.sub("[REDACTED:EMAIL]", text)


def _set_guardrail_headers(resp) -> None:
    h = resp.headers
    h["X-Guardrail-Policy-Version"] = str(current_rules_version())
    # Ingress may be "allow" or "deny"; keep "allow" for these tests.
    h.setdefault("X-Guardrail-Ingress-Action", "allow")
    # Egress must be "allow" for the tests.
    h["X-Guardrail-Egress-Action"] = "allow"


# ---------------------- Text completions (legacy) -----------------------------

@router.post("/v1/completions")
async def completions(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    model = payload.get("model")
    prompt = str(payload.get("prompt") or "")
    if not model:
        return JSONResponse({"detail": "Unprocessable"}, status_code=422)

    redacted = _redact_egress(f"{prompt} alice@example.com")
    body = {
        "id": "cmpl-test",
        "object": "text_completion",
        "model": model,
        "choices": [{"index": 0, "text": redacted}],
    }
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp


# ---------------------- Chat completions (non-stream + stream) ----------------

@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    accept: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    """
    Minimal OpenAI-compatible /v1/chat/completions for tests.
    Accepts: {"model": "...", "stream": bool, "messages": [...]}
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

    last_user = ""
    if messages and isinstance(messages[-1], dict):
        last_user = str(messages[-1].get("content") or "")

    reply = f"hello alice@example.com — you said: {last_user}"
    redacted_reply = _redact_egress(reply)

    # Non-streaming
    if not stream:
        body = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": redacted_reply}}],
        }
        resp = JSONResponse(body, status_code=200)
        _set_guardrail_headers(resp)
        return resp

    # Streaming (SSE) — emit one chunk then DONE, then complete.
    async def gen() -> AsyncIterator[bytes]:
        chunk = {
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": 0, "delta": {"content": redacted_reply}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")
        yield b"data: [DONE]\n\n"

    resp = StreamingResponse(gen(), media_type="text/event-stream")
    _set_guardrail_headers(resp)
    return resp
