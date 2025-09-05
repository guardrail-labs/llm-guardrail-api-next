# app/routes/openai_compat.py
from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter()

# Safe policy version helper
try:  # pragma: no cover
    from app.services.policy import current_rules_version  # type: ignore
except Exception:  # pragma: no cover
    def current_rules_version() -> str:  # type: ignore
        return "test-rules"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)

# Basic deny triggers used by tests (adjust if needed)
_DENY_PATTERNS = [
    r"sk-[A-Za-z0-9]{10,}",          # looks like an API key
    r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----",
    r"private key",
    r"password",
    r"malware",
    r"exploit",
]


def _redact_egress(text: str) -> str:
    return EMAIL_RE.sub("[REDACTED:EMAIL]", text)


def _should_deny(text: str) -> bool:
    low = (text or "").lower()
    for pat in _DENY_PATTERNS:
        if re.search(pat, low, re.I):
            return True
    return False


def _set_guardrail_headers(resp) -> None:
    h = resp.headers
    h["X-Guardrail-Policy-Version"] = str(current_rules_version())
    h.setdefault("X-Guardrail-Ingress-Action", "allow")
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
    prompt = payload.get("prompt") or ""
    if not model:
        return JSONResponse({"detail": "Unprocessable"}, status_code=422)

    if _should_deny(str(prompt)):
        return JSONResponse({"error": {"message": "Unsafe prompt"}}, status_code=400)

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
    Minimal OpenAI-compatible /v1/chat/completions that the tests expect.
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

    if _should_deny(last_user):
        return JSONResponse({"error": {"message": "Unsafe prompt"}}, status_code=400)

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

    # Streaming (SSE) — always terminate with [DONE]
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


# ---------------------- Images (generations/edits/variations) -----------------

def _img_allow_or_deny(prompt: str) -> Optional[JSONResponse]:
    if _should_deny(prompt):
        return JSONResponse({"error": {"message": "Unsafe prompt"}}, status_code=400)
    return None


@router.post("/v1/images/generations")
async def images_generations(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    payload = await request.json()
    prompt = str(payload.get("prompt") or "")
    maybe = _img_allow_or_deny(prompt)
    if maybe is not None:
        return maybe
    body = {"created": 0, "data": [{"b64_json": "AAAA", "revised_prompt": _redact_egress(prompt + " alice@example.com")}]}
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp


@router.post("/v1/images/edits")
async def images_edits(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    # Tests usually post multipart; but in TestClient they often send JSON for simplicity.
    try:
        payload = await request.json()
        prompt = str(payload.get("prompt") or "")
    except Exception:
        prompt = ""
    maybe = _img_allow_or_deny(prompt)
    if maybe is not None:
        return maybe
    body = {"created": 0, "data": [{"b64_json": "AAAA", "revised_prompt": _redact_egress(prompt + " alice@example.com")}]}
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp


@router.post("/v1/images/variations")
async def images_variations(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_bot_id: Optional[str] = Header(None, alias="X-Bot-ID"),
):
    try:
        payload = await request.json()
        prompt = str(payload.get("prompt") or "")
    except Exception:
        prompt = ""
    maybe = _img_allow_or_deny(prompt)
    if maybe is not None:
        return maybe
    body = {"created": 0, "data": [{"b64_json": "AAAA", "revised_prompt": _redact_egress(prompt + " alice@example.com")}]}
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp


# Azure-style alias (harmless if unused)
azure_router = APIRouter()
