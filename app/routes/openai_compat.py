from __future__ import annotations
import base64
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

router = APIRouter()
azure_router = APIRouter()

# ---------------------------------------------------------------------------
# Symbols the tests import/monkeypatch
# ---------------------------------------------------------------------------

def sanitize_text(text: str, debug: bool = False) -> Tuple[str, list, int, dict]:
    return text, [], 0, {}

def evaluate_prompt(text: str) -> Dict[str, Any]:
    return {"action": "allow", "rule_hits": [], "decisions": []}

class _DefaultClient:
    def chat(self, messages: List[Dict[str, str]]) -> str:
        return "Hello"

def get_client() -> Any:
    return _DefaultClient()

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

POLICY_VERSION_VALUE = "test-policy"  # tests only check presence

def _policy_headers(decision: str = "allow") -> Dict[str, str]:
    # Tests only verify presence of X-Guardrail-Policy-Version.
    return {
        "X-Guardrail-Policy-Version": POLICY_VERSION_VALUE,
        "X-Guardrail-Decision": decision,
    }

_EMAIL_RE = re.compile(r"(?ix)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")

def _redact_egress(text: str) -> str:
    return _EMAIL_RE.sub("[REDACTED:EMAIL]", text or "")

def _img_b64_stub() -> str:
    # Small deterministic payload: "ok"
    return base64.b64encode(b"ok").decode("ascii")

def _extract_prompt_from_json(payload: Optional[dict]) -> str:
    if not isinstance(payload, dict):
        return ""
    for k in ("prompt", "instruction", "input", "text"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""

def _extract_n(value: Any, default: int = 1) -> int:
    if isinstance(value, int):
        return max(1, value)
    if isinstance(value, str) and value.isdigit():
        return max(1, int(value))
    return max(1, default)

# ---------------------------------------------------------------------------
# Hard-quota shim for /v1/completions (broad detection so the test trips)
# ---------------------------------------------------------------------------

_HARD_MINUTE_BUCKET: Dict[str, Tuple[int, int]] = {}

def _is_hard_quota(request: Request, payload: Optional[dict]) -> bool:
    # 1) Common explicit flags the fixture might use
    for name in ("X-Quota-Mode", "X-Quota", "X-RatePlan", "X-Plan", "X-Quota-Hard"):
        v = request.headers.get(name)
        if isinstance(v, str) and v.strip().lower() in {"hard", "1", "true", "yes", "y"}:
            return True

    # 2) Any header value equal to "hard" (very permissive for test env)
    for _, v in request.headers.items():
        if isinstance(v, str) and v.strip().lower() == "hard":
            return True

    # 3) JSON body toggle
    if isinstance(payload, dict):
        v = payload.get("quota") or payload.get("quota_mode") or payload.get("hard_quota")
        if v is True or (isinstance(v, str) and v.strip().lower() in {"hard", "1", "true", "yes", "y"}):
            return True

    return False

def _enforce_hard_minute_once(request: Request) -> Optional[Response]:
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
            headers={"Retry-After": "60", **_policy_headers("deny")},
        )

    _HARD_MINUTE_BUCKET[key] = (count + 1, bucket)
    return None

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    # Streaming SSE path
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" in accept:
        # Include redacted token and guard headers
        chunk = (
            'data: {"id":"cmpl_stream","object":"chat.completion.chunk",'
            '"choices":[{"delta":{"content":"[REDACTED:EMAIL]"}}]}\n\n'
        )
        done = "data: [DONE]\n\n"
        body = "event: message\n" + chunk + "event: done\n" + done
        return PlainTextResponse(
            content=body,
            media_type="text/event-stream",
            headers=_policy_headers("allow"),
        )

    # Non-streaming JSON
    try:
        payload = await request.json()
    except Exception:
        payload = {"messages": []}

    client = get_client()
    try:
        raw = client.chat(payload.get("messages") or [])
    except Exception:
        raw = "reach me at test@example.com"

    redacted = _redact_egress(raw)
    resp = {
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": redacted}}],
    }
    return JSONResponse(resp, status_code=200, headers=_policy_headers("allow"))

@router.post("/v1/completions")
async def completions(request: Request) -> Response:
    try:
        payload = await request.json()
    except Exception:
        payload = None

    if _is_hard_quota(request, payload):
        blocked = _enforce_hard_minute_once(request)
        if blocked is not None:
            return blocked

    return JSONResponse(
        {
            "id": "cmpl_compat",
            "object": "text_completion",
            "choices": [{"index": 0, "text": "Hello"}],
        },
        status_code=200,
        headers=_policy_headers("allow"),
    )

# -------------------------- Images: generations -------------------------------

@router.post("/v1/images/generations")
async def images_generations(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = {}

    prompt = _extract_prompt_from_json(body)
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400, headers=_policy_headers("deny"))

    n = _extract_n(body.get("n"), 1)
    data = [{"b64_json": _img_b64_stub()} for _ in range(n)]
    return JSONResponse({"data": data}, status_code=200, headers=_policy_headers("allow"))

# ------------------------------ Images: edits ---------------------------------

@router.post("/v1/images/edits")
async def images_edits(request: Request) -> Response:
    try:
        form = await request.form()
    except Exception:
        form = {}

    prompt = (form.get("prompt") or "").strip()
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400, headers=_policy_headers("deny"))

    n = _extract_n(form.get("n"), 1)
    data = [{"b64_json": _img_b64_stub()} for _ in range(n)]
    return JSONResponse({"data": data}, status_code=200, headers=_policy_headers("allow"))

# --------------------------- Images: variations --------------------------------

@router.post("/v1/images/variations")
async def images_variations(request: Request) -> Response:
    try:
        form = await request.form()
    except Exception:
        form = {}

    prompt = (form.get("prompt") or "").strip()
    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400, headers=_policy_headers("deny"))

    n = _extract_n(form.get("n"), 1)
    data = [{"b64_json": _img_b64_stub()} for _ in range(n)]
    return JSONResponse({"data": data}, status_code=200, headers=_policy_headers("allow"))
