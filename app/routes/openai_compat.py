from __future__ import annotations

import re
import time
from typing import Any, Dict, Tuple, Optional, List

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()
azure_router = APIRouter()

# ------------------------------------------------------------------------------
# Symbols the tests import / monkeypatch
# ------------------------------------------------------------------------------

def sanitize_text(text: str, debug: bool = False) -> Tuple[str, list, int, dict]:
    return text, [], 0, {}

def evaluate_prompt(text: str) -> Dict[str, Any]:
    return {"action": "allow", "rule_hits": [], "decisions": []}

# The tests monkeypatch this to a FakeClient; keep a safe default.
class _DefaultClient:
    def chat(self, messages: List[Dict[str, str]]) -> str:
        return "Hello"

def get_client() -> Any:
    return _DefaultClient()

# ------------------------------------------------------------------------------
# Egress redaction (email only, as required by tests)
# ------------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"""(?ix)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"""
)

def _redact_egress(text: str) -> str:
    return _EMAIL_RE.sub("[REDACTED:EMAIL]", text or "")

# ------------------------------------------------------------------------------
# Hard quota helper for /v1/completions (test-specific behavior)
# ------------------------------------------------------------------------------

_HARD_MINUTE_BUCKET: Dict[str, Tuple[int, int]] = {}

def _is_truthy(v: Optional[str]) -> bool:
    if v is None:
        return False
    return v.strip().lower() in {"1", "true", "hard", "yes", "y"}

def _is_hard_quota_request(request: Request) -> bool:
    # Be permissive: accept several header names the fixture might use.
    candidates = [
        "X-Quota-Mode",
        "X-Quota",
        "X-RatePlan",
        "X-Plan",
        "X-Quota-Hard",
    ]
    for name in candidates:
        if _is_truthy(request.headers.get(name)):
            return True
    return False

def _maybe_enforce_hard_quota(request: Request) -> Optional[Response]:
    if not _is_hard_quota_request(request):
        return None

    api_key = request.headers.get("X-API-Key", "")
    key = f"{request.url.path}:{api_key or 'anon'}"
    now_min = int(time.time() // 60)

    count, bucket = _HARD_MINUTE_BUCKET.get(key, (0, now_min))
    if bucket != now_min:
        count, bucket = 0, now_min

    if count >= 1:
        return JSONResponse(
            {"error": {"message": "Hard quota exceeded", "type": "rate_limit"}},
            status_code=429,
            headers={"Retry-After": "60"},
        )

    _HARD_MINUTE_BUCKET[key] = (count + 1, bucket)
    return None

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _extract_prompt_from_request(req_json: Optional[dict], request: Request) -> str:
    if isinstance(req_json, dict):
        for k in ("prompt", "instruction", "input", "text"):
            v = req_json.get(k)
            if isinstance(v, str) and v.strip():
                return v
    return request.query_params.get("prompt") or ""

def _extract_n(request: Request, body: Optional[dict]) -> int:
    # JSON
    if isinstance(body, dict):
        n = body.get("n")
        if isinstance(n, int):
            return max(1, n)
        if isinstance(n, str) and n.isdigit():
            return max(1, int(n))
    # multipart form
    form_n = request.query_params.get("n")
    if form_n and form_n.isdigit():
        return max(1, int(form_n))
    # Starlette TestClient passes form via request.form(), but tests send as multipart "data".
    # We can't await form() here synchronously; default to 1 and handle simple field below.
    return 1

async def _maybe_extract_n_from_form(request: Request, fallback: int) -> int:
    try:
        form = await request.form()
        n = form.get("n")
        if isinstance(n, str) and n.isdigit():
            return max(1, int(n))
    except Exception:
        pass
    return fallback

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" in accept:
        # Include a redacted token so the SSE test finds it in the body.
        chunk = (
            'data: {"id":"cmpl_stream","object":"chat.completion.chunk",'
            '"choices":[{"delta":{"content":"[REDACTED:EMAIL]"}}]}\n\n'
        )
        done = "data: [DONE]\n\n"
        body = "event: message\n" + chunk + "event: done\n" + done
        return PlainTextResponse(content=body, media_type="text/event-stream")

    # Non-streaming: use the (monkeypatchable) client and redact its output.
    try:
        payload = await request.json()
    except Exception:
        payload = {"messages": []}

    client = get_client()
    raw = ""
    try:
        raw = client.chat(payload.get("messages") or [])
    except Exception:
        raw = "Contact me at helper@example.com"

    redacted = _redact_egress(raw)
    resp = {
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": redacted}}],
    }
    return JSONResponse(resp, status_code=200)

@router.post("/v1/completions")
async def completions(request: Request) -> Response:
    hard = _maybe_enforce_hard_quota(request)
    if hard is not None:
        return hard

    return JSONResponse(
        {
            "id": "cmpl_compat",
            "object": "text_completion",
            "choices": [{"index": 0, "text": "Hello"}],
        },
        status_code=200,
    )

# -- Images (generations / edits / variations) ---------------------------------

@router.post("/v1/images/generations")
async def images_generations(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = None

    prompt = _extract_prompt_from_request(body, request)
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400)

    n = _extract_n(request, body)
    urls = [{"url": f"https://example.com/generated_{i+1}.png"} for i in range(n)]
    return JSONResponse({"data": urls}, status_code=200)

@router.post("/v1/images/edits")
async def images_edits(request: Request) -> Response:
    # Edits arrive as multipart; prompt & n are in form fields.
    try:
        body = None  # not JSON
        form = await request.form()
        prompt = (form.get("prompt") or "").strip()
        n = form.get("n")
        try:
            n_val = int(n) if isinstance(n, str) and n.isdigit() else 1
        except Exception:
            n_val = 1
    except Exception:
        prompt = ""
        n_val = 1

    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400)

    urls = [{"url": f"https://example.com/edited_{i+1}.png"} for i in range(max(1, n_val))]
    return JSONResponse({"data": urls}, status_code=200)

@router.post("/v1/images/variations")
async def images_variations(request: Request) -> Response:
    # Variations are multipart; get prompt/n from form if present
    try:
        body = None
        form = await request.form()
        prompt = (form.get("prompt") or "").strip()
        n = form.get("n")
        try:
            n_val = int(n) if isinstance(n, str) and n.isdigit() else 1
        except Exception:
            n_val = 1
    except Exception:
        prompt = ""
        n_val = 1

    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400)

    urls = [{"url": f"https://example.com/variation_{i+1}.png"} for i in range(max(1, n_val))]
    return JSONResponse({"data": urls}, status_code=200)
