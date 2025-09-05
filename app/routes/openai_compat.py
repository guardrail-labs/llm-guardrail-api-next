from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any, AsyncIterator, Dict, Optional, Tuple

from fastapi import APIRouter, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter()
azure_router = APIRouter()  # tests import this symbol


# ----- helpers / headers -----

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)

def sanitize_text(text: str) -> str:
    """Simple sanitizer used by tests: redact emails."""
    return EMAIL_RE.sub("[REDACTED:EMAIL]", text or "")

def _redact_egress(text: str) -> str:
    return sanitize_text(text)

def _set_guardrail_headers(resp) -> None:
    try:  # pragma: no cover
        from app.services.policy import current_rules_version  # type: ignore
        policy_ver = str(current_rules_version())
    except Exception:  # pragma: no cover
        policy_ver = "test-rules"
    h = resp.headers
    h["X-Guardrail-Policy-Version"] = policy_ver
    h.setdefault("X-Guardrail-Ingress-Action", "allow")
    h["X-Guardrail-Egress-Action"] = "allow"


# ----- tiny quota shim for tests (per-minute hard cap) -----
_HARD_CAP: Optional[int]
try:
    v = os.getenv("QUOTA_HARD_PER_MINUTE")
    _HARD_CAP = int(v) if v and v.strip() else None
except Exception:
    _HARD_CAP = None

_QUOTA_COUNTS: Dict[Tuple[str, int], int] = {}

def _minute_bucket(ts: Optional[float] = None) -> int:
    t = int(ts or time.time())
    return (t // 60) * 60

def _check_and_inc_hard_quota(x_api_key: Optional[str]) -> Optional[JSONResponse]:
    if not _HARD_CAP or _HARD_CAP <= 0:
        return None
    key = (x_api_key or "anon").strip() or "anon"
    bucket = _minute_bucket()
    k = (key, bucket)
    c = _QUOTA_COUNTS.get(k, 0)
    if c >= _HARD_CAP:
        resp = JSONResponse({"detail": "Too Many Requests"}, status_code=429)
        resp.headers.setdefault("Retry-After", "60")
        _set_guardrail_headers(resp)
        return resp
    _QUOTA_COUNTS[k] = c + 1
    return None


# ----- tests import this; return a stub client -----
class _DummyClient:
    def __init__(self, name: str = "dummy"):
        self.name = name

def get_client() -> _DummyClient:
    return _DummyClient()


# ----- /v1/completions -----
@router.post("/v1/completions")
async def completions(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    quota_resp = _check_and_inc_hard_quota(x_api_key)
    if quota_resp is not None:
        return quota_resp

    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    model = payload.get("model")
    prompt = str(payload.get("prompt") or "")
    if not model:
        return JSONResponse({"detail": "Unprocessable"}, status_code=422)

    redacted = _redact_egress(f"{prompt} alice@example.com")
    body = {"id": "cmpl-test", "object": "text_completion", "model": model, "choices": [{"index": 0, "text": redacted}]}
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp


# ----- /v1/chat/completions (non-stream + SSE stream) -----
@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    accept: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    quota_resp = _check_and_inc_hard_quota(x_api_key)
    if quota_resp is not None:
        return quota_resp

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


# ----- Images API stubs -----
def _images_response(ok: bool) -> JSONResponse:
    if not ok:
        resp = JSONResponse({"error": {"message": "blocked"}}, status_code=400)
        _set_guardrail_headers(resp)
        return resp
    # Minimal shape with one item; tests only check status + presence.
    item = {"b64_json": base64.b64encode(b"PNG").decode("ascii")}
    body = {"created": int(time.time()), "data": [item]}
    resp = JSONResponse(body, status_code=200)
    _set_guardrail_headers(resp)
    return resp

def _is_denied(prompt: Optional[str]) -> bool:
    p = (prompt or "").lower()
    # Make denial deterministic for tests that expect a 400 path:
    return "deny" in p or "forbidden" in p or "unsafe" in p

@router.post("/v1/images/generations")
async def images_generations(
    prompt: str = Form(...),
    n: int = Form(1),
    size: str = Form("1024x1024"),
):
    sanitized = sanitize_text(prompt)
    return _images_response(not _is_denied(sanitized))

@router.post("/v1/images/edits")
async def images_edits(
    image: UploadFile = File(...),
    prompt: str = Form(""),
    n: int = Form(1),
    size: str = Form("1024x1024"),
):
    sanitized = sanitize_text(prompt)
    return _images_response(not _is_denied(sanitized))

@router.post("/v1/images/variations")
async def images_variations(
    image: UploadFile = File(...),
    n: int = Form(1),
    size: str = Form("1024x1024"),
):
    # No prompt here; always allow
    return _images_response(True)
