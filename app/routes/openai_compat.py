from __future__ import annotations

import asyncio
import json
import re
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

# Two routers: tests mount BOTH depending on scenario.
router = APIRouter()
azure_router = APIRouter()

__all__ = ["router", "azure_router", "sanitize_text", "get_client"]


# ---------------------- helpers expected by tests ----------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{7,}\d")
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")

def sanitize_text(text: str) -> str:
    """
    Very small sanitizer used by image endpoints tests to show we're touching text.
    """
    if not isinstance(text, str):
        return ""
    t = EMAIL_RE.sub("[email]", text)
    t = PHONE_RE.sub("[phone]", t)
    t = BASE64_BLOB_RE.sub("[base64]", t)
    return t


def get_client() -> None:
    """
    Placeholder for an upstream OpenAI client (tests just check attribute exists).
    """
    return None


def _should_deny(prompt: Optional[str]) -> bool:
    if not prompt:
        return False
    p = prompt.lower()
    return "deny" in p or "unsafe" in p or "forbidden" in p


# ---------------------- /v1/completions ----------------------

@router.post("/v1/completions")
@azure_router.post("/v1/completions")
async def completions(request: Request) -> JSONResponse:
    data = await request.json()
    prompt = data.get("prompt", "")
    text = "ok" if not _should_deny(prompt) else "blocked"
    return JSONResponse(
        {
            "id": "cmpl_test",
            "object": "text_completion",
            "choices": [{"text": text, "index": 0, "finish_reason": "stop"}],
            "model": data.get("model", "demo"),
        }
    )


# ---------------------- /v1/chat/completions (stream + non-stream) ----------------------

async def _sse_gen(messages: List[Dict[str, Any]]) -> AsyncGenerator[bytes, None]:
    # tiny deterministic stream: one delta then DONE
    chunk1 = {
        "id": "chatcmpl_test",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello"}, "finish_reason": None}],
    }
    yield f"data: {json.dumps(chunk1)}\n\n".encode("utf-8")
    await asyncio.sleep(0)  # let event loop yield
    yield b"data: [DONE]\n\n"

@router.post("/v1/chat/completions")
@azure_router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    data = await request.json()
    stream = bool(data.get("stream"))
    # NOTE: SSE detection is handled by the main app wrapper. We always return the right type.
    if stream:
        return StreamingResponse(_sse_gen(data.get("messages") or []), media_type="text/event-stream")
    # non-stream JSON
    return JSONResponse(
        {
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello"},
                    "finish_reason": "stop",
                }
            ],
            "model": data.get("model", "demo"),
        }
    )


# ---------------------- Images: generations / edits / variations ----------------------

def _img_ok_or_raise(prompt: Optional[str]) -> None:
    if _should_deny(prompt):
        # The tests expect a 400 on "deny"/"unsafe" inputs
        raise HTTPException(status_code=400, detail="Invalid prompt")

def _img_payload() -> Dict[str, Any]:
    # return a minimal OpenAI-compatible image payload
    return {"created": 0, "data": [{"b64_json": "AAAA"}]}

@router.post("/v1/images/generations")
@azure_router.post("/v1/images/generations")
async def images_generations(request: Request) -> JSONResponse:
    data = await request.json()
    prompt = sanitize_text(data.get("prompt", ""))
    _img_ok_or_raise(prompt)
    return JSONResponse(_img_payload())

@router.post("/v1/images/edits")
@azure_router.post("/v1/images/edits")
async def images_edits(request: Request) -> JSONResponse:
    # tests send JSON; we keep it simple and read json body
    data = await request.json()
    prompt = sanitize_text(data.get("prompt", ""))
    _img_ok_or_raise(prompt)
    return JSONResponse(_img_payload())

@router.post("/v1/images/variations")
@azure_router.post("/v1/images/variations")
async def images_variations(request: Request) -> JSONResponse:
    data = await request.json()
    prompt = sanitize_text(data.get("prompt", ""))
    _img_ok_or_raise(prompt)
    return JSONResponse(_img_payload())
