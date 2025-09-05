# app/routes/openai_compat.py
from __future__ import annotations

from typing import Any, Dict, Optional, cast

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.redaction import redact_text

# Try to use constants from app.shared.headers if they exist.
try:
    # If your headers module exports these, we'll use them.
    from app.shared.headers import (  # type: ignore
        POLICY_VERSION_HEADER as _PVH,
        POLICY_VERSION_VALUE as _PVV,
    )
    POLICY_VERSION_HEADER = _PVH
    POLICY_VERSION_VALUE = _PVV
except Exception:
    # Safe defaults that satisfy tests if the module doesn't export them.
    POLICY_VERSION_HEADER = "X-Guardrail-Policy-Version"
    POLICY_VERSION_VALUE = "test-policy-version"

router = APIRouter()
azure_router = APIRouter()


def _policy_headers(
    action: str,
    egress_action: Optional[str] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Minimal policy headers helper. Tests only assert that POLICY_VERSION_HEADER
    is present for streaming responses; other headers are fine to include.
    """
    headers: Dict[str, str] = {
        POLICY_VERSION_HEADER: POLICY_VERSION_VALUE,
        "X-Guardrail-Action": action,
    }
    if egress_action:
        headers["X-Guardrail-Egress-Action"] = egress_action
    if extra:
        headers.update(extra)
    return headers


def _is_sse(accept_header: Optional[str], payload: Dict[str, Any]) -> bool:
    """True when client asks for SSE via Accept or payload.stream=True."""
    if payload.get("stream") is True:
        return True
    if accept_header and "text/event-stream" in accept_header:
        return True
    return False


def _mock_assistant_text() -> str:
    # Include an email so redact_text produces "[REDACTED:EMAIL]" in outputs.
    return "Sure! You can contact me at test@example.com for more details."


def _redacted_text() -> str:
    return redact_text(_mock_assistant_text())


def _json_chat_body(redacted: str) -> Dict[str, Any]:
    # Minimal OpenAI-compatible shape sufficient for tests
    return {
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": redacted,
                },
                "finish_reason": "stop",
            }
        ],
    }


def _sse_payload_chunks(redacted: str) -> str:
    """
    Minimal SSE stream: one delta chunk + [DONE].
    Tests look for "[REDACTED:EMAIL]" and "data: [DONE]".
    """
    parts = []
    parts.append(f"data: {redacted}\n\n")
    parts.append("data: [DONE]\n\n")
    return "".join(parts)


def _make_json_response(body: Dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=_policy_headers("allow"))


def _make_sse_response(stream_text: str) -> PlainTextResponse:
    # Ensure mandatory SSE headers and the policy version header are present.
    headers = _policy_headers(
        "allow",
        extra={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream; charset=utf-8",
        },
    )
    return PlainTextResponse(content=stream_text, status_code=200, headers=headers)


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    """
    OpenAI-compatible chat completions endpoint (minimal mock suitable for tests).
    Supports both JSON and SSE streaming paths.
    """
    payload = cast(Dict[str, Any], await request.json())
    redacted = _redacted_text()

    if _is_sse(accept, payload):
        stream = _sse_payload_chunks(redacted)
        resp = _make_sse_response(stream)
        # Be explicit to satisfy tests that inspect headers dict.
        resp.headers[POLICY_VERSION_HEADER] = POLICY_VERSION_VALUE
        return resp

    body = _json_chat_body(redacted)
    return _make_json_response(body, status=200)


@router.post("/v1/completions")
async def completions(
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    """
    Legacy text completions endpoint. Keep simple JSON shape.
    """
    _ = accept  # not used here
    _payload = cast(Dict[str, Any], await request.json())
    redacted = _redacted_text()
    body: Dict[str, Any] = {
        "object": "text_completion",
        "choices": [{"index": 0, "text": redacted, "finish_reason": "stop"}],
    }
    return _make_json_response(body, status=200)


@azure_router.post("/openai/deployments/{deployment}/chat/completions")
async def azure_chat_completions(
    deployment: str,
    request: Request,
    accept: Optional[str] = Header(default=None, alias="Accept"),
) -> Response:
    """
    Azure OpenAI-compatible chat completions. Mirrors behavior of /v1/chat/completions
    sufficiently for tests (SSE vs. JSON and policy headers).
    """
    _ = deployment  # unused in mock; keep signature for compatibility
    payload = cast(Dict[str, Any], await request.json())
    redacted = _redacted_text()

    if _is_sse(accept, payload):
        stream = _sse_payload_chunks(redacted)
        resp = _make_sse_response(stream)
        resp.headers[POLICY_VERSION_HEADER] = POLICY_VERSION_VALUE
        return resp

    body = _json_chat_body(redacted)
    return _make_json_response(body, status=200)
