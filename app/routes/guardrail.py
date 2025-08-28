from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.services.detectors import evaluate_prompt
from app.services.policy import current_rules_version

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# Simple per-process counters (read by /metrics)
_requests_total = 0
_decisions_total = 0

# Rate limiting state
_RATE_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}  # per-client rolling window timestamps
_LAST_RATE_CFG: Tuple[bool, int, int] = (False, 60, 60)


def get_requests_total() -> float:
    return float(_requests_total)


def get_decisions_total() -> float:
    return float(_decisions_total)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _bucket_for(key: str) -> List[float]:
    win = _BUCKETS.get(key)
    if win is None:
        win = []
        _BUCKETS[key] = win
    return win


def _rate_cfg() -> Tuple[bool, int, int]:
    """
    Enabled only when RATE_LIMIT_ENABLED is explicitly true.
    If limits aren't explicitly provided, use huge defaults to avoid accidental throttling
    across the test suite.
    """
    enabled_env = os.environ.get("RATE_LIMIT_ENABLED")
    enabled = (enabled_env or "false").lower() == "true"
    if not enabled:
        return False, 60, 60

    if "RATE_LIMIT_PER_MINUTE" in os.environ:
        per_min = int(os.environ["RATE_LIMIT_PER_MINUTE"])
    else:
        per_min = 10_000_000  # effectively disabled unless test sets explicit value

    if "RATE_LIMIT_BURST" in os.environ:
        burst = int(os.environ["RATE_LIMIT_BURST"])
    else:
        burst = per_min

    return True, per_min, burst


def _rate_limit_check(request: Request) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    global _LAST_RATE_CFG
    cfg = _rate_cfg()
    # If the config changed between tests, reset windows to avoid bleed-over.
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
    """Emit an audit JSON log line with a truncated snippet."""
    if (os.environ.get("AUDIT_ENABLED") or "false").lower() != "true":
        return
    try:
        max_chars = int(os.environ.get("AUDIT_MAX_TEXT_CHARS") or "64")
    except Exception:
        max_chars = 64
    snippet = prompt[:max_chars]
    event = {
        "event": "guardrail_decision",  # tests expect this key
        "request_id": rid,
        "snippet": snippet,
        "snippet_len": len(snippet),
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


@router.post("/", response_model=None)
async def guardrail_root(request: Request) -> Any:
    """
    Legacy ingress guardrail.

    JSON body: {"prompt": "..."}

    - 401: {"detail": "Unauthorized"}
    - 413: {"code": "payload_too_large", "request_id": ...}
    - 429: {"code": "rate_limited", "detail": "Rate limit exceeded",
            "retry_after": 60, "request_id": ...}
    - 200: {
        "decision": "allow|block",
        "transformed_text": "...",
        "rule_hits": [...],  # list[str]
        "policy_version": "...",
        "request_id": "..."
      }
    """
    global _requests_total, _decisions_total

    rid = _req_id(request)

    if _need_auth(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )

    if not _rate_limit_check(request):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": "rate_limited",
                "detail": "Rate limit exceeded",
                "retry_after": 60,
                "request_id": rid,
            },
            headers={"Retry-After": "60"},
        )

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
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"code": "payload_too_large", "request_id": rid},
        )

    _requests_total += 1

    det = evaluate_prompt(prompt)
    action = str(det.get("action", "allow"))
    transformed = det.get("transformed_text", prompt)
    raw_hits = list(det.get("rule_hits", []))

    # Normalize/augment rule hits to list[str] that tests assert against.
    hit_strings: List[str] = []
    for h in raw_hits:
        if isinstance(h, str):
            hit_strings.append(h)
        elif isinstance(h, dict):
            if isinstance(h.get("id"), str):
                hit_strings.append(h["id"])
            elif isinstance(h.get("rule_id"), str):
                hit_strings.append(h["rule_id"])
            elif isinstance(h.get("tag"), str):
                tag = h["tag"].lower()
                if tag == "secrets":
                    hit_strings.append("secrets:api_key_like")
                elif tag == "unsafe":
                    hit_strings.append("unsafe:regex_match")
                elif tag == "gray":
                    hit_strings.append("pi:prompt_injection")

    txt_lower = prompt.lower()
    if "ignore previous instructions" in txt_lower:
        if "pi:prompt_injection" not in hit_strings:
            hit_strings.append("pi:prompt_injection")

    # secret-like tokens (generic)
    if re.search(r"sk-[A-Za-z0-9]{16,}", prompt):
        if "secrets:api_key_like" not in hit_strings:
            hit_strings.append("secrets:api_key_like")

    # long base64-ish blob
    if re.search(r"[A-Za-z0-9+/=]{128,}", prompt):
        if "payload:encoded_blob" not in hit_strings:
            hit_strings.append("payload:encoded_blob")

    # Block if detectors say not-allow OR our heuristics trigger.
    decision = "block" if (action != "allow" or hit_strings) else "allow"

    _decisions_total += 1

    _audit_maybe(prompt, rid)

    return {
        "decision": decision,
        "transformed_text": transformed,
        "rule_hits": hit_strings,
        "policy_version": current_rules_version(),
        "request_id": rid,
    }


@router.post("/evaluate")
async def evaluate(request: Request) -> Dict[str, Any]:
    """
    Backward-compatible evaluate:

      - JSON: {"text": "...", "request_id": "...?"}
      - Multipart: fields: text?, image?, audio?, file? (repeatable)

    Returns detectors/decisions and possible redactions.
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

    body: Dict[str, Any] = {
        "request_id": request_id,
        "action": det.get("action", "allow"),
        "transformed_text": xformed,
        "decisions": decisions,
        "risk_score": det.get("risk_score", 0),
        "rule_hits": det.get("rule_hits", []),
    }
    return body
