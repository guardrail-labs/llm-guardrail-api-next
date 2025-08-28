from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.services.detectors import evaluate_prompt
from app.services.policy import current_rules_version, reload_rules

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# Ensure a static policy file (if provided) is loaded once when AUTORELOAD=false
_STATIC_RULES_LOADED = False

# Simple per-process counters (read by /metrics)
_requests_total = 0
_decisions_total = 0

# Rate limiting state (per-process token buckets)
_RATE_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}  # per-client rolling window timestamps
_LAST_RATE_CFG: Tuple[bool, int, int] = (False, 60, 60)


def get_requests_total() -> float:
    return float(_requests_total)


def get_decisions_total() -> float:
    return float(_decisions_total)


def _client_key(request: Request) -> str:
    # Key by client + api key to isolate tests/users
    host = request.client.host if request.client else "unknown"
    api = request.headers.get("x-api-key") or ""
    return f"{host}:{api}"


def _bucket_for(key: str) -> List[float]:
    win = _BUCKETS.get(key)
    if win is None:
        win = []
        _BUCKETS[key] = win
    return win


def _app_rate_cfg(request: Request) -> Tuple[bool, int, int]:
    """
    Prefer app.state (set at app creation) to avoid cross-test env bleed.
    Fall back to environment if state attributes are missing.
    """
    st = getattr(request.app, "state", None)
    if st and hasattr(st, "rate_limit_enabled"):
        enabled = bool(getattr(st, "rate_limit_enabled"))
        per_min = int(getattr(st, "rate_limit_per_minute", 60))
        burst = int(getattr(st, "rate_limit_burst", per_min))
        return enabled, per_min, burst

    # Fallback: environment (kept for backward-compat and local runs)
    enabled = (os.environ.get("RATE_LIMIT_ENABLED") or "false").lower() == "true"
    per_min = int(os.environ.get("RATE_LIMIT_PER_MINUTE") or "60")
    burst = int(os.environ.get("RATE_LIMIT_BURST") or str(per_min))
    return enabled, per_min, burst


def _rate_limit_check(request: Request) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    global _LAST_RATE_CFG
    cfg = _app_rate_cfg(request)
    # If the config changed (e.g., new test app), reset windows.
    if cfg != _LAST_RATE_CFG:
        with _RATE_LOCK:
            _BUCKETS.clear()
            _LAST_RATE_CFG = cfg

    enabled, _per_min, burst = cfg
    if not enabled:
        return True

    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        win = _bucket_for(key)
        cutoff = now - 60.0
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            return False
        win.append(now)
        return True


def _need_auth(request: Request) -> bool:
    # Either header is accepted by tests.
    return not (
        request.headers.get("x-api-key") or request.headers.get("authorization")
    )


def _req_id(request: Request) -> str:
    return request.headers.get("x-request-id") or str(uuid.uuid4())


def _audit_maybe(prompt: str, rid: str) -> None:
    """
    Emit a JSON line to logger 'guardrail_audit' with truncated snippet.
    Fields:
      - event: "guardrail_decision"
      - request_id: str
      - snippet: truncated text
      - snippet_len: int
      - snippet_truncated: bool
    """
    if (os.environ.get("AUDIT_ENABLED") or "false").lower() != "true":
        return
    try:
        max_chars = int(os.environ.get("AUDIT_MAX_TEXT_CHARS") or "64")
    except Exception:
        max_chars = 64
    snippet = prompt[:max_chars]
    event = {
        "event": "guardrail_decision",
        "request_id": rid,
        "snippet": snippet,
        "snippet_len": len(snippet),
        "snippet_truncated": len(prompt) > len(snippet),
    }
    logging.getLogger("guardrail_audit").info(json.dumps(event))


def _read_json_payload(payload: Dict[str, Any]) -> Tuple[str, str]:
    text = str(payload.get("text", ""))
    request_id = payload.get("request_id") or str(uuid.uuid4())
    return text, request_id


async def _read_multipart_payload(
    request: Request,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """
    Accepts fields: text?, image?, audio?, file? (repeatable).
    Produces unified text by appending placeholders for each uploaded asset.
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
            decisions.append({"type": "normalized", "tag": kind, "filename": filename})

    for kind in ("image", "audio", "file"):
        append_files(kind)

    return text, request_id, decisions


def _maybe_load_static_rules_once() -> None:
    """When AUTORELOAD=false and a rules path is provided, load it once."""
    global _STATIC_RULES_LOADED
    if _STATIC_RULES_LOADED:
        return
    auto = (os.environ.get("POLICY_AUTORELOAD") or "false").lower() == "true"
    if not auto:
        path = os.environ.get("POLICY_RULES_PATH")
        if path:
            try:
                reload_rules()
            except Exception:
                # If reload fails, continue; built-in defaults still apply.
                pass
    _STATIC_RULES_LOADED = True


@router.post("/", response_model=None)
async def guardrail_root(request: Request, response: Response) -> Dict[str, Any]:
    """
    Legacy ingress guardrail.

    JSON body: {"prompt": "..."}

    - 401: {"detail": "Unauthorized"}
    - 413: {"code": "payload_too_large", "request_id": ...}
    - 429: {
        "code": "rate_limited",
        "detail": "Rate limit exceeded",
        "retry_after": 60,
        "request_id": ...
      }
    - 200: {
        "decision": "allow|block",
        "transformed_text": "...",
        "rule_hits": [...],
        "policy_version": "...",
        "request_id": "..."
      }
    """
    global _requests_total, _decisions_total

    _maybe_load_static_rules_once()
    rid = _req_id(request)

    if _need_auth(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )

    # Rate-limit before parsing payload
    if not _rate_limit_check(request):
        retry_after = 60
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        response.headers["Retry-After"] = str(retry_after)
        return {
            "code": "rate_limited",
            "detail": "Rate limit exceeded",
            "retry_after": int(retry_after),
            "request_id": rid,
        }

    try:
        payload = await request.json()
    except Exception:
        payload = {}
    prompt = str(payload.get("prompt", ""))

    try:
        max_chars = int(os.environ.get("MAX_PROMPT_CHARS") or "0")
    except Exception:
        max_chars = 0
    if max_chars and len(prompt) > max_chars:
        response.status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        return {"code": "payload_too_large", "request_id": rid}

    _requests_total += 1

    # Use detectors for rule_hits and transformed text; map to legacy "block".
    det = evaluate_prompt(prompt)
    action = str(det.get("action", "allow"))
    decision = "block" if action != "allow" else "allow"
    transformed = det.get("transformed_text", prompt)
    rule_hits = list(det.get("rule_hits", []))

    _decisions_total += 1

    # Audit log line
    _audit_maybe(prompt, rid)

    return {
        "decision": decision,
        "transformed_text": transformed,
        "rule_hits": rule_hits,
        "policy_version": current_rules_version(),
        "request_id": rid,
    }


@router.post("/evaluate", response_model=None)
async def evaluate(request: Request) -> Dict[str, Any]:
    """
    Backward-compatible evaluate:

      - JSON: {"text": "...", "request_id": "...?"}
      - Multipart: fields: text?, image?, audio?, file? (repeatable)

    Returns detectors/decisions and possible redactions.
    """
    global _requests_total, _decisions_total

    _maybe_load_static_rules_once()
    _requests_total += 1

    content_type = (request.headers.get("content-type") or "").lower()
    decisions: List[Dict[str, Any]] = []

    if content_type.startswith("application/json"):
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        text, request_id = _read_json_payload(
            payload if isinstance(payload, dict) else {}
        )
    elif content_type.startswith("multipart/form-data"):
        text, request_id, norm_decisions = await _read_multipart_payload(request)
        decisions.extend(norm_decisions)
    else:
        try:
            payload = await request.json()
            text, request_id = _read_json_payload(
                payload if isinstance(payload, dict) else {}
            )
        except Exception:
            text, request_id = "", str(uuid.uuid4())

    det = evaluate_prompt(text)
    decisions.extend(det.get("decisions", []))

    # If text changed, surface a redaction decision for tests.
    xformed = det.get("transformed_text", text)
    if xformed != text:
        decisions.append({"type": "redaction", "changed": True})

    _decisions_total += 1

    # Contract expects action "allow" here, even when redactions occur.
    # Other routes (e.g., /guardrail) surface a block/allow decision.
    body: Dict[str, Any] = {
        "request_id": request_id,
        "action": "allow",
        "transformed_text": xformed,
        "decisions": decisions,
        "risk_score": det.get("risk_score", 0),
        "rule_hits": det.get("rule_hits", []),
    }
    return body
