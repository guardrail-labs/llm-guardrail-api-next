from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from app.redaction import redact_text
from app.routes.shared import (
    _policy_headers,
    attach_guardrail_headers,
    POLICY_VERSION_VALUE,
)

# Routers expected by tests
router = APIRouter()
azure_router = APIRouter()


def _extract_user_text_from_messages(messages: Any) -> str:
    """
    Pull a reasonable assistant reply based on the last user message.
    Tests validate shape, streaming markers, redaction, and headers.
    """
    try:
        msgs = messages or []
        if not isinstance(msgs, list):
            return "Acknowledged."
        for m in reversed(msgs):
            role = (m.get("role") or "").lower() if isinstance(m, dict) else ""
            if role == "user":
                c = m.get("content") if isinstance(m, dict) else ""
                # If content is a list of parts, flatten to text where possible
                if isinstance(c, list):
                    parts: List[str] = []
                    for p in c:
                        if isinstance(p, dict):
                            if "text" in p and isinstance(p["text"], str):
                                parts.append(p["text"])
                            elif "content" in p and isinstance(p["content"], str):
                                parts.append(p["content"])
                        elif isinstance(p, str):
                            parts.append(p)
                    c = " ".join(parts)
                elif not isinstance(c, str):
                    c = str(c)
                return c or "Acknowledged."
        return "Acknowledged."
    except Exception:
        return "Acknowledged."


def _sse_response_from_text(text: str) -> Response:
    """
    Build a minimal, valid OpenAI-style SSE stream with required headers.
    """
    redacted_stream_piece = redact_text(text)

    lines: List[str] = []
    # role delta
    lines.append(
        'data: {"id":"chatcmpl-demo","object":"chat.completion.chunk",'
        '"choices":[{"index":0,"delta":{"role":"assistant"}}]}'
    )
    # content delta
    lines.append(
        'data: {"id":"chatcmpl-demo","object":"chat.completion.chunk",'
        '"choices":[{"index":0,"delta":{"content":"'
        + redacted_stream_piece.replace('"', '\\"')
        + '"}}]}'
    )
    # sentinel
    lines.append("data: [DONE]")
    body = "\n".join(lines) + "\n\n"

    resp = PlainTextResponse(
        body,
        media_type="text/event-stream",
        headers=_policy_headers("allow", egress_action="allow"),
    )
    attach_guardrail_headers(resp, decision="allow", egress_action="allow")
    # Ensure the specific header asserted by tests
    resp.headers["X-Guardrail-Policy-Version"] = POLICY_VERSION_VALUE
    # Helpful streaming headers
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["Connection"] = "keep-alive"
    return resp


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    payload: Dict[str, Any],
    accept: str = Header(default="*/*"),
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
    x_tenant_id: Optional[str] = Header(default=None, convert_underscores=False),
    x_bot_id: Optional[str] = Header(default=None, convert_underscores=False),
) -> Response:
    """
    Minimal OpenAI-compatible /v1/chat/completions used by tests.

    - When Accept includes text/event-stream and payload.stream is True,
      returns SSE with [DONE].
    - Otherwise returns a JSON chat completion object.
    - Always applies redact_text on the output.
    - Always sets guardrail policy headers; streaming explicitly sets
      X-Guardrail-Policy-Version for the test assertion.
    - Ensures `resp` is a Response instance (mypy fix).
    """
    messages = payload.get("messages")
    assistant_text = _extract_user_text_from_messages(messages)
    redacted = redact_text(assistant_text)

    wants_stream = bool(payload.get("stream")) and ("text/event-stream" in (accept or "").lower())
    if wants_stream:
        return _sse_response_from_text(assistant_text)

    # Non-streaming JSON path
    payload_body: Dict[str, Any] = {
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": redacted},
            }
        ],
    }

    resp = JSONResponse(
        payload_body,
        status_code=200,
        headers=_policy_headers("allow", egress_action="allow"),
    )
    attach_guardrail_headers(resp, decision="allow", egress_action="allow")
    resp.headers["X-Guardrail-Policy-Version"] = POLICY_VERSION_VALUE
    return resp


@router.post("/v1/completions")
async def completions_legacy(
    request: Request,
    payload: Dict[str, Any],
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
    x_tenant_id: Optional[str] = Header(default=None, convert_underscores=False),
    x_bot_id: Optional[str] = Header(default=None, convert_underscores=False),
) -> Response:
    """
    Minimal legacy /v1/completions endpoint used by metrics/quotas tests.
    Returns a stubbed completion-like shape and sets guardrail headers.
    """
    prompt = payload.get("prompt") or ""
    if isinstance(prompt, list):
        prompt = " ".join([p for p in prompt if isinstance(p, str)])
    elif not isinstance(prompt, str):
        prompt = str(prompt)

    redacted = redact_text(prompt or "Acknowledged.")

    body = {
        "id": "cmpl-demo",
        "object": "text_completion",
        "choices": [{"index": 0, "text": redacted}],
    }

    resp = JSONResponse(
        body,
        status_code=200,
        headers=_policy_headers("allow", egress_action="allow"),
    )
    attach_guardrail_headers(resp, decision="allow", egress_action="allow")
    resp.headers["X-Guardrail-Policy-Version"] = POLICY_VERSION_VALUE
    return resp


# Azure-compatible routes reusing the same behavior.
@azure_router.post("/openai/deployments/{deployment}/chat/completions")
async def azure_chat_completions(
    request: Request,
    deployment: str,
    payload: Dict[str, Any],
    accept: str = Header(default="*/*"),
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
    x_tenant_id: Optional[str] = Header(default=None, convert_underscores=False),
    x_bot_id: Optional[str] = Header(default=None, convert_underscores=False),
) -> Response:
    return await chat_completions(request, payload, accept, x_api_key, x_tenant_id, x_bot_id)


@azure_router.post("/openai/deployments/{deployment}/completions")
async def azure_completions_legacy(
    request: Request,
    deployment: str,
    payload: Dict[str, Any],
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
    x_tenant_id: Optional[str] = Header(default=None, convert_underscores=False),
    x_bot_id: Optional[str] = Header(default=None, convert_underscores=False),
) -> Response:
    return await completions_legacy(request, payload, x_api_key, x_tenant_id, x_bot_id)
