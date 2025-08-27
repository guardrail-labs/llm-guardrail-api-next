from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Dict, Tuple, cast

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from app.routes.schema import GuardrailRequest, GuardrailResponse, OutputGuardrailRequest
from app.services.policy import evaluate_and_apply, get_settings

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# ---------
# Metrics
# ---------
_requests_total: int = 0
_decisions_total: int = 0


def get_requests_total() -> int:
    return _requests_total


def get_decisions_total() -> int:
    return _decisions_total


# ----------------
# Rate limiter
# ----------------
@dataclass
class Bucket:
    tokens: float
    last: float


# Kept for type reference; actual buckets are stored on app.state
_buckets: Dict[str, Bucket] = {}


def _int_env(v) -> int:
    try:
        return int(v) if v not in (None, "") else 0
    except (TypeError, ValueError):
        return 0


def _extract_request_id(request: Request) -> str:
    rid = request.headers.get("X-Request-ID") or request.headers.get("x-request-id")
    return rid or str(uuid.uuid4())


def _attach_request_id(resp: JSONResponse, rid: str) -> None:
    resp.headers["X-Request-ID"] = rid


def _security_headers(resp: JSONResponse) -> None:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"


def _is_authorized(request: Request) -> bool:
    # Accept X-API-Key or any non-empty Authorization (bearer) token
    if request.headers.get("X-API-Key"):
        return True
    if request.headers.get("Authorization"):
        return True
    return False


def _rate_limit(request: Request, now: float) -> Tuple[bool, int]:
    s = get_settings()
    enabled = str(getattr(s, "RATE_LIMIT_ENABLED", "false")).lower() in (
        "1",
        "true",
        "yes",
    )
    if not enabled:
        return True, 0

    per_min = _int_env(getattr(s, "RATE_LIMIT_PER_MINUTE", 60))
    burst = _int_env(getattr(s, "RATE_LIMIT_BURST", per_min))
    if per_min <= 0 or burst <= 0:
        # misconfigured -> don't limit
        return True, 0

    # Buckets are stored per-app to avoid cross-test bleed
    if not hasattr(request.app.state, "rate_buckets"):
        request.app.state.rate_buckets = {}  # type: ignore[attr-defined]
    buckets: Dict[str, Bucket] = cast(
        Dict[str, Bucket], request.app.state.rate_buckets  # type: ignore[attr-defined]
    )

    # Use API key if present; otherwise Authorization; client IP; then global
    key = (
        request.headers.get("X-API-Key")
        or request.headers.get("Authorization")
        or (request.client.host if request.client else None)
        or "global"
    )

    rate_per_sec = per_min / 60.0
    b = buckets.get(key)
    if b is None:
        b = Bucket(tokens=float(burst), last=now)
        buckets[key] = b
    else:
        elapsed = max(0.0, now - b.last)
        b.tokens = min(float(burst), b.tokens + elapsed * rate_per_sec)
        b.last = now

    if b.tokens >= 1.0:
        b.tokens -= 1.0
        return True, 0

    # calculate retry_after seconds until next token
    need = 1.0 - b.tokens
    retry_after = max(1, int(need / rate_per_sec))
    return False, retry_after


@router.post("", response_model=GuardrailResponse)
def guard(
    ingress: GuardrailRequest, request: Request, s=Depends(get_settings)
) -> JSONResponse:
    global _requests_total, _decisions_total
    _requests_total += 1

    req_id = _extract_request_id(request)

    # Robust limit parsing (413 enforced here)
    max_chars = _int_env(
        getattr(s, "MAX_PROMPT_CHARS", None) or getattr(s, "PROMPT_MAX_CHARS", 0)
    )
    if max_chars and len(ingress.prompt) > max_chars:
        resp = JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "code": "payload_too_large",
                "detail": "Prompt too large",
                "request_id": req_id,
            },
        )
        _attach_request_id(resp, req_id)
        _security_headers(resp)
        return resp

    # Require API key (401 unless disabled entirely)
    if not _is_authorized(request):
        resp = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": req_id},
        )
        resp.headers["WWW-Authenticate"] = "Bearer"
        _attach_request_id(resp, req_id)
        _security_headers(resp)
        return resp

    # Rate limit check
    ok, retry_after = _rate_limit(request, time.time())
    if not ok:
        resp = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": "rate_limited",
                "retry_after": retry_after,
                "request_id": req_id,
            },
        )
        resp.headers["Retry-After"] = str(retry_after)
        _attach_request_id(resp, req_id)
        _security_headers(resp)
        return resp

    payload = evaluate_and_apply(ingress.prompt, request_id=req_id)
    _decisions_total += 1

    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GuardrailResponse(**payload).model_dump(),
    )
    _attach_request_id(resp, req_id)
    _security_headers(resp)
    return resp


@router.post("/output")
def guard_output(
    ingress: OutputGuardrailRequest, request: Request, s=Depends(get_settings)
) -> JSONResponse:
    req_id = _extract_request_id(request)

    # Require auth for parity with main endpoint
    if not _is_authorized(request):
        resp = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized", "request_id": req_id},
        )
        resp.headers["WWW-Authenticate"] = "Bearer"
        _attach_request_id(resp, req_id)
        _security_headers(resp)
        return resp

    # Output size limit 413
    output_max = _int_env(getattr(s, "OUTPUT_MAX_CHARS", 0))
    if output_max and len(ingress.output) > output_max:
        resp = JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "code": "too_large",
                "detail": "Output too large",
                "request_id": req_id,
            },
        )
        _attach_request_id(resp, req_id)
        _security_headers(resp)
        return resp

    # Reuse evaluate for redaction and reasoning surface
    payload = evaluate_and_apply(ingress.output, request_id=req_id)
    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "ok": True,
            "request_id": req_id,
            "transformed_text": payload["transformed_text"],
            "decision": payload["decision"],
        },
    )
    _attach_request_id(resp, req_id)
    _security_headers(resp)
    return resp
