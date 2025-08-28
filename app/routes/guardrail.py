from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, Request, Response, status

from app.services import policy
from app.services.detectors import evaluate_prompt

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# Simple per-process counters (read by /metrics)
_requests_total = 0
_decisions_total = 0

_RATE_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}  # per-client rolling window timestamps


def get_requests_total() -> float:
    return float(_requests_total)


def get_decisions_total() -> float:
    return float(_decisions_total)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_cfg() -> Tuple[bool, int, int]:
    enabled = (os.environ.get("RATE_LIMIT_ENABLED") or "true").lower() == "true"
    per_min = int(os.environ.get("RATE_LIMIT_PER_MINUTE") or "60")
    burst = int(os.environ.get("RATE_LIMIT_BURST") or str(per_min))
    return enabled, per_min, burst


def _rate_limit_remaining(request: Request) -> int:
    enabled, per_min, burst = _rate_cfg()
    if not enabled:
        return per_min
    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        win = _BUCKETS.setdefault(key, [])
        cutoff = now - 60.0
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            return 0
        win.append(now)
        return max(0, per_min - len(win))


def _need_auth(request: Request) -> bool:
    # Either X-API-Key or Authorization is required by tests
    return not (
        request.headers.get("x-api-key")
        or request.headers.get("authorization")
    )


def _req_id(request: Request) -> str:
    return request.headers.get("x-request-id") or str(uuid.uuid4())


def _json_error(code: int, request_id: str, message: str) -> Dict[str, Any]:
    return {"code": code, "request_id": request_id, "message": message}


def _size_limit(var_name: str) -> int:
    try:
        return int(os.environ.get(var_name, "0"))
    except Exception:
        return 0


def _read_json_payload(payload: Dict[str, Any]) -> Tuple[str, str]:
    text = str(payload.get("text", ""))
    request_id = payload.get("request_id") or str(uuid.uuid4())
    return text, request_id


async def _read_multipart_payload(
    request: Request,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """
    Accepts fields:
      - text: optional str
      - image/audio/file: one or many files
    Produces a unified text by appending placeholders for each uploaded asset.
    """
    form = await request.form()
    text = str(form.get("text") or "")
    request_id = str(form.get("request_id") or str(uuid.uuid4()))
    decisions: List[Dict[str, Any]] = []

    def append_files(kind: str) -> None:
        nonlocal text
        items = form.getlist(kind)
        for f in items:
            filename = getattr(f, "filename", "upload")
            text += f" [{kind.upper()}:{filename}]"
            decisions.append(
                {"type": "normalized", "tag": kind, "filename": filename}
            )

    for kind in ("image", "audio", "file"):
        append_files(kind)

    return text, request_id, decisions


# ---------- Legacy root guardrail endpoint ----------

@router.post("/")
async def guardrail_root(request: Request) -> Response:
    """
    Legacy inbound guardrail used heavily in tests.
    JSON: {"prompt": "..."}
    Auth required. Applies rate limits and size limit.
    Returns 200 with {"action", "transformed_text", "decisions"}.
    On 401/413/429 returns JSON with {"code", "request_id", "message"}.
    """
    global _requests_total, _decisions_total

    rid = _req_id(request)

    # Auth check
    if _need_auth(request):
        err_body = _json_error(401, rid, "Missing API key or Authorization")
        resp = Response(
            content=json.dumps(err_body),
            media_type="application/json",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        resp.headers["X-Request-ID"] = rid
        return resp

    # Rate limiting
    remaining = _rate_limit_remaining(request)
    if remaining == 0:
        err_body = _json_error(429, rid, "Rate limit exceeded")
        resp = Response(
            content=json.dumps(err_body),
            media_type="application/json",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
        resp.headers["Retry-After"] = "60"
        resp.headers["X-Request-ID"] = rid
        return resp

    # Parse payload
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    prompt = str(payload.get("prompt", ""))

    # Size check
    max_chars = _size_limit("MAX_PROMPT_CHARS")
    if max_chars and len(prompt) > max_chars:
        err_body = _json_error(413, rid, "Prompt too large")
        resp = Response(
            content=json.dumps(err_body),
            media_type="application/json",
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
        resp.headers["X-Request-ID"] = rid
        return resp

    _requests_total += 1

    # Apply policies; map to legacy "block" semantics:
    # if any hit in {unsafe, gray, secrets} => action="deny", else "allow"
    res = policy.apply_policies(prompt)
    hits = {h.get("tag") for h in res.get("hits", [])}
    action = "deny" if ({"unsafe", "gray", "secrets"} & hits) else "allow"

    transformed = res.get("sanitized_text", prompt)
    redactions = int(res.get("redactions", 0))

    decisions: List[Dict[str, Any]] = []
    for h in res.get("hits", []):
        decisions.append(
            {"type": "rule_hit", "tag": h.get("tag"), "pattern": h.get("pattern")}
        )
    if redactions:
        decisions.append({"type": "redaction", "changed": True, "count": redactions})

    resp_body: Dict[str, Any] = {
        "action": action,
        "transformed_text": transformed,
        "decisions": decisions,
    }

    _decisions_total += 1

    resp = Response(
        content=json.dumps(resp_body),
        media_type="application/json",
        status_code=status.HTTP_200_OK,
    )
    resp.headers["X-Request-ID"] = rid
    return resp


# ---------- Evaluate endpoint (always "allow") ----------

@router.post("/evaluate")
async def evaluate(request: Request) -> Dict[str, Any]:
    """
    Backward-compatible:
      - JSON: {"text": "...", "request_id": "...?"}
      - Multipart: fields: text?, image?, audio?, file? (repeatable)
    Contract requires action="allow" (even when redactions occur).
    """
    global _requests_total, _decisions_total

    _requests_total += 1

    content_type = (request.headers.get("content-type") or "").lower()
    decisions: List[Dict[str, Any]] = []

    if content_type.startswith("application/json"):
        payload = await request.json()
        text, request_id = _read_json_payload(
            payload if isinstance(payload, dict) else {}
        )
    elif content_type.startswith("multipart/form-data"):
        text, request_id, norm_decisions = await _read_multipart_payload(request)
        decisions.extend(norm_decisions)
    else:
        # Be forgiving: try JSON, else treat as empty
        try:
            payload = await request.json()
            text, request_id = _read_json_payload(
                payload if isinstance(payload, dict) else {}
            )
        except Exception:
            text, request_id = "", str(uuid.uuid4())

    # Run detectors + policy application (sanitization, scoring, action)
    det = evaluate_prompt(text)
    decisions.extend(det.get("decisions", []))

    _decisions_total += 1

    # Force allow for this specific endpoint's contract
    return {
        "request_id": request_id,
        "action": "allow",
        "transformed_text": det.get("transformed_text", text),
        "decisions": decisions,
        "risk_score": det.get("risk_score", 0),
        "rule_hits": det.get("rule_hits", []),
    }
