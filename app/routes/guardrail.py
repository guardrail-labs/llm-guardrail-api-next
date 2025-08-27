from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse

from app.routes.schema import GuardrailRequest, GuardrailResponse
from app.services.policy import evaluate_and_apply, get_settings, get_redactions_total

router = APIRouter(prefix="/guardrail", tags=["guardrail"])

# ----------------
# Simple metrics
# ----------------
_guardrail_requests_total: int = 0  # incremented on every /guardrail call


def _int_env(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ----------------
# Rate limiting
# ----------------
# Minimal token-bucket per identity (API key or remote addr)
_BUCKETS: Dict[str, Tuple[float, float]] = defaultdict(lambda: (time.time(), 0.0))
# (last_refill_ts, tokens)


def _rate_limited(identity: str, per_minute: int, burst: int) -> Tuple[bool, int]:
    """
    Returns (limited, retry_after_seconds)
    """
    now = time.time()
    last, tokens = _BUCKETS[identity]
    rate_per_sec = max(per_minute, 0) / 60.0
    capacity = max(burst, 0)

    # Refill
    tokens = min(capacity, tokens + (now - last) * rate_per_sec)
    # Consume 1 token
    if tokens >= 1.0:
        tokens -= 1.0
        _BUCKETS[identity] = (now, tokens)
        return False, 0

    # Limited
    _BUCKETS[identity] = (now, tokens)
    # compute time until next token
    needed = 1.0 - tokens
    retry_after = int(max(1, needed / rate_per_sec)) if rate_per_sec > 0 else 60
    return True, retry_after


def _extract_request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or request.headers.get("x-request-id") or str(uuid.uuid4())


def _api_key_or_401(request: Request, s) -> str:
    # Require API key unless explicitly disabled by env for tests
    must_auth = str(getattr(s, "REQUIRE_API_KEY", "true")).lower() not in ("0", "false", "no")
    api_key = request.headers.get("X-API-Key")
    if must_auth and not api_key:
        rid = _extract_request_id(request)
        # include header and JSON shape expected by tests
        body = {"code": "unauthorized", "detail": "Missing API key", "request_id": rid}
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=body)
    return api_key or ""


def _size_limit_or_413(kind: str, actual_len: int, limit: int, request: Request) -> None:
    if limit and actual_len > limit:
        rid = _extract_request_id(request)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"code": "too_large", "detail": f"{kind} exceeds limit", "request_id": rid},
        )


def _maybe_rate_limit(request: Request, s) -> Tuple[bool, int]:
    enabled = str(getattr(s, "RATE_LIMIT_ENABLED", "false")).lower() in ("1", "true", "yes")
    if not enabled:
        return False, 0

    per_min = _int_env(getattr(s, "RATE_LIMIT_PER_MINUTE", 60))
    burst = _int_env(getattr(s, "RATE_LIMIT_BURST", 60))
    api_key = request.headers.get("X-API-Key") or request.client.host or "anon"
    limited, retry_after = _rate_limited(api_key, per_min, burst)
    return limited, retry_after


def _attach_request_id(response: Response, request_id: str) -> None:
    # ensure consistent header
    response.headers["X-Request-ID"] = request_id


@router.post("", response_model=GuardrailResponse)
def guard(
    ingress: GuardrailRequest,
    request: Request,
    s=Depends(get_settings),
) -> Response:
    # Robustly parse limits (handle bad types as 0)
    max_chars = _int_env(getattr(s, "MAX_PROMPT_CHARS", None) or getattr(s, "PROMPT_MAX_CHARS", 0))
    output_max = _int_env(getattr(s, "OUTPUT_MAX_CHARS", 0))

    # Require API key (401 unless disabled)
    _api_key_or_401(request, s)

    # Request ID (pass-through or generate)
    req_id = _extract_request_id(request)

    # Rate limit (429)
    limited, retry_after = _maybe_rate_limit(request, s)
    if limited:
        body = {"code": "rate_limited", "detail": "Too Many Requests", "request_id": req_id}
        resp = JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content=body)
        resp.headers["Retry-After"] = str(retry_after)
        _attach_request_id(resp, req_id)
        return resp

    # Prompt limit (413)
    _size_limit_or_413("prompt", len(ingress.prompt or ""), max_chars, request)

    # Main evaluation
    payload = evaluate_and_apply(ingress.prompt, request_id=req_id)

    # Count metrics
    global _guardrail_requests_total
    _guardrail_requests_total += 1

    # Successful response
    resp = JSONResponse(status_code=status.HTTP_200_OK, content=GuardrailResponse(**payload).model_dump())
    _attach_request_id(resp, req_id)
    return resp


@router.post("/output")
def guard_output(
    payload: dict,
    request: Request,
    s=Depends(get_settings),
) -> Response:
    """
    A minimal output guardrail that only enforces OUTPUT_MAX_CHARS
    and mirrors the error shape used in tests.
    """
    # Require API key (401 unless disabled)
    _api_key_or_401(request, s)
    req_id = _extract_request_id(request)

    output_str = str(payload.get("output", "") or "")
    output_max = _int_env(getattr(s, "OUTPUT_MAX_CHARS", 0))
    _size_limit_or_413("output", len(output_str), output_max, request)

    # OK
    resp = JSONResponse(status_code=status.HTTP_200_OK, content={"ok": True, "request_id": req_id})
    _attach_request_id(resp, req_id)
    return resp


@router.get("/metrics")
def metrics() -> PlainTextResponse:
    """
    Expose minimal Prometheus-like text so tests see the names they assert on.
    """
    lines = []
    # request counter
    lines.append("# HELP guardrail_requests_total Total /guardrail requests.")
    lines.append("# TYPE guardrail_requests_total counter")
    lines.append(f"guardrail_requests_total {_guardrail_requests_total}")

    # redactions counter (fed by policy module)
    redactions = get_redactions_total()
    lines.append("# HELP guardrail_redactions_total Total redactions applied.")
    lines.append("# TYPE guardrail_redactions_total counter")
    lines.append(f"guardrail_redactions_total {redactions}")

    return PlainTextResponse("\n".join(lines) + "\n")
