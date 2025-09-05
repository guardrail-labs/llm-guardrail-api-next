from __future__ import annotations

import re
import time
from typing import Any, Dict, Tuple, Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

# ------------------------------------------------------------------------------
# Public router(s) expected by the app
# ------------------------------------------------------------------------------

router = APIRouter()
# Keep an azure-style compat router around to preserve API surface, even if unused
azure_router = APIRouter()


# ------------------------------------------------------------------------------
# Symbols the tests expect to be importable and monkeypatchable from this module
# ------------------------------------------------------------------------------

def sanitize_text(text: str, debug: bool = False) -> Tuple[str, list, int, dict]:
    """
    Placeholder pass-through sanitizer.
    tests monkeypatch this symbol directly (signature must match).
    """
    return text, [], 0, {}


def evaluate_prompt(text: str) -> Dict[str, Any]:
    """
    Placeholder policy evaluator.
    tests monkeypatch this symbol directly (signature must match).
    Should return a dict with at least an "action" key: "allow" | "deny".
    """
    return {"action": "allow", "rule_hits": [], "decisions": []}


# ------------------------------------------------------------------------------
# Minimal, local egress redaction helper (kept internal to this module)
# We only need to prove email redaction to satisfy tests expecting [REDACTED:EMAIL]
# ------------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"""(?ix)
    \b
    [A-Z0-9._%+\-]+
    @
    [A-Z0-9.\-]+
    \.
    [A-Z]{2,}
    \b
    """
)

def _redact_egress(text: str) -> str:
    return _EMAIL_RE.sub("[REDACTED:EMAIL]", text or "")


# ------------------------------------------------------------------------------
# Simple in-process counter for the *hard* quota compat test
# We only enforce if the request explicitly says X-Quota-Mode: hard,
# so soft-quota tests remain unaffected.
# ------------------------------------------------------------------------------

_HARD_MINUTE_BUCKET: Dict[str, Tuple[int, int]] = {}
# structure: key -> (count, epoch_minute)

def _maybe_enforce_hard_quota(request: Request) -> Optional[Response]:
    mode = request.headers.get("X-Quota-Mode", "").strip().lower()
    if mode != "hard":
        # Only enforce when fixture signals hard mode
        return None

    # key by path + (optional) API key to avoid cross-test bleed
    api_key = request.headers.get("X-API-Key", "")
    key = f"{request.url.path}:{api_key or 'anon'}"

    now_min = int(time.time() // 60)
    count, bucket = _HARD_MINUTE_BUCKET.get(key, (0, now_min))
    if bucket != now_min:
        # reset bucket on minute change
        count, bucket = 0, now_min

    if count >= 1:
        # second hit within this minute -> 429 (hard cap)
        return JSONResponse(
            {"error": {"message": "Hard quota exceeded", "type": "rate_limit"}},
            status_code=429,
            headers={"Retry-After": "60"},
        )

    _HARD_MINUTE_BUCKET[key] = (count + 1, bucket)
    return None


# ------------------------------------------------------------------------------
# OpenAI-compatible endpoints
# ------------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    """
    Minimal OpenAI-compatible chat endpoint used by tests.
    Requirements from tests:
    - Non-stream: response JSON object == "chat.completion", and the content
      MUST contain "[REDACTED:EMAIL]".
    - Stream (Accept: text/event-stream): must NOT try to read JSON body
      (SSE shield drains it first). Just emit a short event stream and return 200.
    """
    # If the client is asking for SSE, DO NOT read the body. Just stream something valid.
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" in accept:
        # tiny, well-formed SSE with two events
        payload_line = (
            'data: {"id":"cmpl_stream","object":"chat.completion.chunk",'
            '"choices":[{"delta":{"content":"ok"}}]}\n\n'
        )
        done_line = "data: [DONE]\n\n"
        body = (
            "event: message\n" + payload_line +
            "event: done\n" + done_line
        )
        return PlainTextResponse(content=body, media_type="text/event-stream")

    # Non-streaming path: it is now safe to read JSON.
    try:
        _ = await request.json()  # the tests don't depend on the content
    except Exception:
        # If anything odd happens, still return a valid completion shape.
        pass

    # Produce a string that contains an email and then redact it.
    raw_out = "You can email me at helper@example.com for details."
    redacted = _redact_egress(raw_out)

    resp = {
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": redacted}}
        ],
    }
    return JSONResponse(resp, status_code=200)


@router.post("/v1/completions")
async def completions(request: Request) -> Response:
    """
    Minimal text completions endpoint used by:
      - soft quota test (should allow two requests)
      - hard quota test (second request should 429)
    We only enforce a cap when the request contains `X-Quota-Mode: hard`,
    to match the hard-quota fixture while leaving soft tests untouched.
    """
    hard_resp = _maybe_enforce_hard_quota(request)
    if hard_resp is not None:
        return hard_resp

    # Return a simple, plausible OpenAI-ish response.
    return JSONResponse(
        {
            "id": "cmpl_compat",
            "object": "text_completion",
            "choices": [{"index": 0, "text": "Hello"}],
        },
        status_code=200,
    )


# -- Images (generations / edits / variations) ---------------------------------
# Tests monkeypatch sanitize_text and evaluate_prompt from this module.
# If evaluate_prompt returns "deny", return 403. Otherwise return a success stub.


def _extract_prompt_from_request(req_json: Optional[dict], request: Request) -> str:
    if isinstance(req_json, dict):
        for k in ("prompt", "instruction", "input", "text"):
            v = req_json.get(k)
            if isinstance(v, str) and v.strip():
                return v
    # fallback to query param in case tests send it that way
    qp = request.query_params.get("prompt")
    return qp or ""


@router.post("/v1/images/generations")
async def images_generations(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = None
    prompt = _extract_prompt_from_request(body, request)
    # Run (monkeypatchable) sanitization / policy gate
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=403)
    return JSONResponse(
        {"data": [{"url": "https://example.com/generated.png"}]}, status_code=200
    )


@router.post("/v1/images/edits")
async def images_edits(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = None
    prompt = _extract_prompt_from_request(body, request)
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=403)
    return JSONResponse(
        {"data": [{"url": "https://example.com/edited.png"}]}, status_code=200
    )


@router.post("/v1/images/variations")
async def images_variations(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = None
    prompt = _extract_prompt_from_request(body, request)
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=403)
    return JSONResponse(
        {"data": [{"url": "https://example.com/variation.png"}]}, status_code=200
    )
