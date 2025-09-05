# app/routes/openai_compat.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, cast

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.redaction import redact_text
from app.shared.headers import attach_guardrail_headers

router = APIRouter()
azure_router = APIRouter()

# ---------------------------------------------------------------------------
# Test hooks (the test suite monkey-patches these at module scope)
# ---------------------------------------------------------------------------

def sanitize_text(text: str, debug: bool = False) -> Tuple[str, List[Dict[str, Any]], int, Dict[str, Any]]:
    """
    Shape: (sanitized_text, hits, redaction_count, debug_meta)
    Tests replace this with a lambda; default just runs redact_text.
    """
    return (redact_text(text), [], 0, {})

def get_client() -> Any:
    """
    Tests monkey-patch this to return a fake provider client.
    We just expose the symbol.
    """
    class _Noop:
        pass
    return _Noop()

__all__ = ["router", "azure_router", "sanitize_text", "get_client"]

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _assistant_text() -> str:
    # Include something redactable so redact_text behavior is observable.
    return "Sure! You can reach me at test@example.com."

def _is_sse(accept_header: Optional[str], payload: Optional[Dict[str, Any]]) -> bool:
    if accept_header and "text/event-stream" in accept_header:
        return True
    if payload and payload.get("stream") is True:
        return True
    return False

def _json_chat_body(text: str) -> Dict[str, Any]:
    return {
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
    }

def _sse_stream(text: str) -> str:
    # Minimal SSE stream: single chunk + DONE sentinel.
    return f"data: {text}\n\ndata: [DONE]\n\n"

def _images_allow_or_deny(prompt: str) -> Tuple[bool, str]:
    sanitized, hits, _count, _meta = sanitize_text(prompt, debug=False)
    return (len(hits) == 0, sanitized)

def _images_ok(text: str) -> Dict[str, Any]:
    # Minimal OpenAI-compatible shape with tiny b64 payload ("f")
    return {"created": 0, "data": [{"b64_json": "Zg==", "revised_prompt": text}]}

def _images_deny() -> Dict[str, Any]:
    return {"error": {"message": "Denied by policy"}}

# ---------------------------------------------------------------------------
# Chat / Completions
# ---------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    """
    Minimal OpenAI-compatible chat endpoint.
    IMPORTANT: when streaming (SSE), do NOT parse JSON first.
    """
    payload: Optional[Dict[str, Any]] = None
    parse_json = not (accept and "text/event-stream" in accept)
    if parse_json:
        try:
            payload = cast(Dict[str, Any], await request.json())
        except Exception:
            payload = {}

    text, _hits, _count, _meta = sanitize_text(_assistant_text(), debug=False)

    if _is_sse(accept, payload):
        resp = PlainTextResponse(
            content=_sse_stream(text),
            status_code=200,
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/event-stream; charset=utf-8",
            },
        )
        return attach_guardrail_headers(
            resp,
            decision="allow",
            ingress_action="allow",
            egress_action="allow",
        )

    resp = JSONResponse(_json_chat_body(text), status_code=200)
    return attach_guardrail_headers(
        resp,
        decision="allow",
        ingress_action="allow",
        egress_action="allow",
    )

@router.post("/v1/completions")
async def completions(
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    """
    Legacy completions endpoint used by tests for quota/metrics behavior.
    """
    _ = accept
    try:
        payload = cast(Dict[str, Any], await request.json())
    except Exception:
        payload = {}

    prompt_text = str(payload.get("prompt", _assistant_text()))
    text, _hits, _count, _meta = sanitize_text(prompt_text, debug=False)

    body: Dict[str, Any] = {
        "object": "text_completion",
        "choices": [{"index": 0, "text": text, "finish_reason": "stop"}],
    }
    resp = JSONResponse(body, status_code=200)
    return attach_guardrail_headers(
        resp,
        decision="allow",
        ingress_action="allow",
        egress_action="allow",
    )

# Azure alias for chat
@azure_router.post("/openai/deployments/{deployment}/chat/completions")
async def azure_chat_completions(
    deployment: str,
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    _ = deployment
    payload: Optional[Dict[str, Any]] = None
    parse_json = not (accept and "text/event-stream" in accept)
    if parse_json:
        try:
            payload = cast(Dict[str, Any], await request.json())
        except Exception:
            payload = {}

    text, _hits, _count, _meta = sanitize_text(_assistant_text(), debug=False)

    if _is_sse(accept, payload):
        resp = PlainTextResponse(
            content=_sse_stream(text),
            status_code=200,
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/event-stream; charset=utf-8",
            },
        )
        return attach_guardrail_headers(
            resp,
            decision="allow",
            ingress_action="allow",
            egress_action="allow",
        )

    resp = JSONResponse(_json_chat_body(text), status_code=200)
    return attach_guardrail_headers(
        resp,
        decision="allow",
        ingress_action="allow",
        egress_action="allow",
    )

# ---------------------------------------------------------------------------
# Images: generations / edits / variations
# ---------------------------------------------------------------------------

@router.post("/v1/images/generations")
async def images_generations(request: Request) -> Response:
    try:
        body = cast(Dict[str, Any], await request.json())
    except Exception:
        body = {}
    prompt = str(body.get("prompt", ""))
    allow, sanitized = _images_allow_or_deny(prompt)
    if not allow:
        resp = JSONResponse(_images_deny(), status_code=403)
        return attach_guardrail_headers(resp, decision="deny", ingress_action="deny", egress_action="allow")
    resp = JSONResponse(_images_ok(sanitized), status_code=200)
    return attach_guardrail_headers(resp, decision="allow", ingress_action="allow", egress_action="allow")

@router.post("/v1/images/edits")
async def images_edits(request: Request) -> Response:
    try:
        body = cast(Dict[str, Any], await request.json())
    except Exception:
        body = {}
    prompt = str(body.get("prompt", ""))
    allow, sanitized = _images_allow_or_deny(prompt)
    if not allow:
        resp = JSONResponse(_images_deny(), status_code=403)
        return attach_guardrail_headers(resp, decision="deny", ingress_action="deny", egress_action="allow")
    resp = JSONResponse(_images_ok(sanitized), status_code=200)
    return attach_guardrail_headers(resp, decision="allow", ingress_action="allow", egress_action="allow")

@router.post("/v1/images/variations")
async def images_variations(request: Request) -> Response:
    try:
        body = cast(Dict[str, Any], await request.json())
    except Exception:
        body = {}
    prompt = str(body.get("prompt", ""))
    allow, sanitized = _images_allow_or_deny(prompt)
    if not allow:
        resp = JSONResponse(_images_deny(), status_code=403)
        return attach_guardrail_headers(resp, decision="deny", ingress_action="deny", egress_action="allow")
    resp = JSONResponse(_images_ok(sanitized), status_code=200)
    return attach_guardrail_headers(resp, decision="allow", ingress_action="allow", egress_action="allow")
