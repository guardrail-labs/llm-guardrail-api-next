from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response

from app.services.detectors import evaluate_prompt

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# Simple per-process counters (you already read these in /metrics)
_requests_total = 0
_decisions_total = 0

_RATE_LOCK = threading.RLock()
_BUCKET: Dict[str, List[float]] = {}
_MAX_PER_MIN = 60


def get_requests_total() -> float:
    return float(_requests_total)


def get_decisions_total() -> float:
    return float(_decisions_total)


def _rate_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limit(request: Request) -> None:
    now = time.time()
    key = _rate_key(request)
    with _RATE_LOCK:
        win = _BUCKET.setdefault(key, [])
        cutoff = now - 60
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= _MAX_PER_MIN:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
            )
        win.append(now)


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
      - image: one or many files
      - audio: one or many files
      - file:  one or many files (pdf/doc/etc.)
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
            # f is an UploadFile; we do not read bytes here
            filename = getattr(f, "filename", "upload")
            text += f" [{kind.upper()}:{filename}]"
            decisions.append({"type": "normalized", "tag": kind, "filename": filename})

    for kind in ("image", "audio", "file"):
        append_files(kind)

    return text, request_id, decisions


@router.post("/evaluate")
async def evaluate(request: Request) -> Dict[str, Any]:
    """
    Backward-compatible:
      - JSON: {"text": "...", "request_id": "...?"}
      - Multipart: fields: text?, image?, audio?, file? (repeatable)
    Returns unified response with detectors/decisions and possible redactions.
    """
    global _requests_total, _decisions_total

    _rate_limit(request)
    _requests_total += 1

    content_type = (request.headers.get("content-type") or "").lower()
    decisions: List[Dict[str, Any]] = []

    if content_type.startswith("application/json"):
        payload = await request.json()
        text, request_id = _read_json_payload(payload if isinstance(payload, dict) else {})
    elif content_type.startswith("multipart/form-data"):
        text, request_id, norm_decisions = await _read_multipart_payload(request)
        decisions.extend(norm_decisions)
    else:
        # Be forgiving: try JSON, else treat as empty
        try:
            payload = await request.json()
            text, request_id = _read_json_payload(payload if isinstance(payload, dict) else {})
        except Exception:
            text, request_id = "", str(uuid.uuid4())

    # Run detectors + policy application (sanitization, scoring, action)
    det = evaluate_prompt(text)
    decisions.extend(det.get("decisions", []))

    _decisions_total += 1

    # Use actual decision coming from detectors/policy (tests expect sanitize/deny/clarify when applicable)
    body: Dict[str, Any] = {
        "request_id": request_id,
        "action": det.get("action", "allow"),
        "transformed_text": det.get("transformed_text", text),
        "decisions": decisions,
        "risk_score": det.get("risk_score", 0),
        "rule_hits": det.get("rule_hits", []),
    }
    return body
