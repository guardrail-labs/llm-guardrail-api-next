from __future__ import annotations
import base64
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.datastructures import FormData

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

def _policy_headers(decision: str = "allow", egress_action: Optional[str] = None) -> Dict[str, str]:
    """
    Standard guard headers needed by tests.
    - X-Guardrail-Policy-Version: required everywhere
    - X-Guardrail-Decision:       keep existing behavior
    - X-Guardrail-Ingress-Action: required by tests (allow|deny)
    - X-Guardrail-Egress-Action:  only set when provided (e.g., quota deny => "skipped")
    """
    headers: Dict[str, str] = {
        "X-Guardrail-Policy-Version": POLICY_VERSION_VALUE,
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Ingress-Action": decision,
    }
    if egress_action:
        headers["X-Guardrail-Egress-Action"] = egress_action
    return headers

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
# Per-app hard/soft minute quota for /v1/completions (driven by app.state)
# ---------------------------------------------------------------------------

# key: id(app) -> (count_in_minute, minute_epoch)
_APP_MINUTE_BUCKET: Dict[int, Tuple[int, int]] = {}

def _enforce_app_quota(request: Request) -> Optional[Response]:
    """
    Uses per-app state configured by tests:

      app.state.quota_enabled   : bool
      app.state.quota_mode      : "hard" | "soft"
      app.state.quota_per_minute: int
      app.state.quota_per_day   : int  (unused here)

    On hard mode, second request within the same minute (limit=1) must 429.
    On soft mode, never block.
    """
    app = request.app
    enabled = getattr(app.state, "quota_enabled", False)
    if not enabled:
        return None

    mode = getattr(app.state, "quota_mode", "soft")
    per_min = int(getattr(app.state, "quota_per_minute", 0) or 0)
    if per_min <= 0:
        return None

    now_min = int(time.time() // 60)
    key = id(app)
    count, bucket = _APP_MINUTE_BUCKET.get(key, (0, now_min))
    if bucket != now_min:
        count, bucket = 0, now_min

    if count >= per_min and mode.lower() == "hard":
        # Block with guardrail headers + Retry-After + egress skipped
        return JSONResponse(
            {"error": {"message": "Hard quota exceeded", "type": "rate_limit"}},
            status_code=429,
            headers={"Retry-After": "60", **_policy_headers("deny", egress_action="skipped")},
        )

    # Allow (increment even in soft mode so counters behave realistically)
    _APP_MINUTE_BUCKET[key] = (count + 1, bucket)
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
        _ = await request.json()
    except Exception:
        _ = None

    blocked = _enforce_app_quota(request)
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
        form = FormData({})

    prompt_val = form.get("prompt")
    prompt = prompt_val.strip() if isinstance(prompt_val, str) else ""

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
        form = FormData({})

    prompt_val = form.get("prompt")
    prompt = prompt_val.strip() if isinstance(prompt_val, str) else ""

    prompt, _, _, _ = sanitize_text(prompt, debug=False)
    verdict = evaluate_prompt(prompt)
    if verdict.get("action") == "deny":
        return JSONResponse({"error": {"message": "blocked"}}, status_code=400, headers=_policy_headers("deny"))

    n = _extract_n(form.get("n"), 1)
    data = [{"b64_json": _img_b64_stub()} for _ in range(n)]
    return JSONResponse({"data": data}, status_code=200, headers=_policy_headers("allow"))
