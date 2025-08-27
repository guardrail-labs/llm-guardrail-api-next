from __future__ import annotations

import time
import uuid
from typing import Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.routes.schema import GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply, get_settings, get_redactions_total

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# ----------------
# Simple metrics
# ----------------
_guardrail_requests_total: int = 0  # incremented on every /guardrail call


def get_requests_total() -> int:
    return _guardrail_requests_total


def _int_env(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ----------------
# Rate limiting
# ----------------
# token-bucket per identity (API key or remote addr)
# stored as identity -> (last_refill_ts, tokens, initialized)
_BUCKETS: Dict[str, Tuple[float, float, bool]] = {}


def _rate_limited(identity: str, per_minute: int, burst: int) -> Tuple[bool, int]:
    """
    Returns (limited, retry_after_seconds).
    First 'burst' requests are allowed immediately.
    """
    now = time.time()
    rate_per_sec = max(per_minute, 0) / 60.0
    capacity = max(burst, 0)

    last, tokens, initialized = _BUCKETS.get(identity, (now, float(capacity), False))

    # On the very first seen request, give full burst capacity and consume 1.
    if not initialized:
        tokens = float(capacity)
        initialized = True

    # Refill
    elapsed = max(0.0, now - last)
    tokens = min(capacity, tokens + elapsed * rate_per_sec)

    # Consume 1 token
    if tokens >= 1.0:
        tokens -= 1.0
        _BUCKETS[identity] = (now, tokens, initialized)
        return False, 0

    # Limited
    _BUCKETS[identity] = (now, tokens, initialized)
    needed = 1.0 - tokens
    retry_after = int(max(1, needed / rate_per_sec)) if rate_per_sec > 0 else 60
    return True, retry_after


def _extract_request_id(request: Request) -> str:
    rid = request.headers.get("X-Request-ID") or request.headers.get("x-request-id")
    return rid or str(uuid.uuid4())


def _auth_or_401(request: Request, s) -> None:
    """
    Accept either X-API-Key or Authorization (bearer) header.
    If neither is present and auth is required, return 401 with detail string.
    """
    must_auth = str(getattr(s, "REQUIRE_API_KEY", "true")).lower() not in ("0", "false", "no")
    if not must_auth:
        return

    if request.headers.get("X-API-Key"):
        return
    if request.headers.get("Authorization"):
        return

    # tests expect {"detail": "Unauthorized"} at the top level
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def _size_limit_prompt_or_413(prompt_len: int, limit: int, req_id: str) -> JSONResponse | None:
    if limit and prompt_len > limit:
        # tests expect top-level code payload_too_large
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"code": "payload_too_large", "request_id": req_id},
        )
    return None


def _size_limit_output_or_413(output_len: int, limit: int, req_id: str) -> JSONResponse | None:
    if limit and output_len > limit:
        # tests expect top-level detail string containing "Output too large"
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Output too large", "request_id": req_id},
        )
    return None


def _maybe_rate_limit(request: Request, s) -> Tuple[bool, int]:
    enabled = str(getattr(s, "RATE_LIMIT_ENABLED", "false")).lower() in ("1", "true", "yes")
    if not enabled:
        return False, 0
    per_min = _int_env(getattr(s, "RATE_LIMIT_PER_MINUTE", 60))
    burst = _int_env(getattr(s, "RATE_LIMIT_BURST", 60))
    ident = request.headers.get("X-API-Key") or request.headers.get("Authorization") or "anon"
    return _rate_limited(ident, per_min, burst)


def _attach_request_id(response: Response, request_id: str) -> None:
    response.headers["X-Request-ID"] = request_id


@router.post("", response_model=GuardrailResponse)
def guard(
    ingress: GuardrailRequest,
    request: Request,
    s=Depends(get_settings),
) -> Response:
    # Require auth (401 with detail string)
    _auth_or_401(request, s)

    # Request ID
    req_id = _extract_request_id(request)

    # Rate limit (allow first 'burst' requests)
    limited, retry_after = _maybe_rate_limit(request, s)
    if limited:
        resp = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"code": "rate_limited", "request_id": req_id},
        )
        resp.headers["Retry-After"] = str(retry_after)
        _attach_request_id(resp, req_id)
        return resp

    # Prompt size limit
    max_chars = _int_env(getattr(s, "MAX_PROMPT_CHARS", None) or getattr(s, "PROMPT_MAX_CHARS", 0))
    pre = _size_limit_prompt_or_413(len(ingress.prompt or ""), max_chars, req_id)
    if pre is not None:
        _attach_request_id(pre, req_id)
        return pre

    # Main evaluation
    payload = evaluate_and_apply(ingress.prompt, request_id=req_id)

    # Count metrics
    global _guardrail_requests_total
    _guardrail_requests_total += 1

    # 200 OK with schema
    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GuardrailResponse(**payload).model_dump(),
    )
    _attach_request_id(resp, req_id)
    return resp


@router.post("/output")
def guard_output(
    payload: dict,
    request: Request,
    s=Depends(get_settings),
) -> Response:
    # Require auth (401 with detail string)
    _auth_or_401(request, s)
    req_id = _extract_request_id(request)

    # Enforce output size limit
    output_str = str(payload.get("output", "") or "")
    output_max = _int_env(getattr(s, "OUTPUT_MAX_CHARS", 0))
    pre = _size_limit_output_or_413(len(output_str), output_max, req_id)
    if pre is not None:
        _attach_request_id(pre, req_id)
        return pre

    # Reuse evaluate for redactions/metrics; decision may be "allow" or "block"
    body = evaluate_and_apply(output_str, request_id=req_id)

    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GuardrailResponse(**body).model_dump(),
    )
    _attach_request_id(resp, req_id)
    return resp
