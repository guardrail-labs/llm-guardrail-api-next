from __future__ import annotations

import logging
import math
import re
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple, TypeVar

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.middleware.request_id import get_request_id
from app.services.ratelimit import (
    RATE_LIMIT_BLOCKS,
    RATE_LIMIT_SKIPS,
    RateLimiter,
    get_enforce_unknown,
    get_global,
)

_log = logging.getLogger(__name__)

T = TypeVar("T")


def _best_effort(msg: str, fn: Callable[[], T], default: Optional[T] = None) -> Optional[T]:
    try:
        return fn()
    except Exception as exc:  # pragma: no cover
        # nosec B110 - rate limit metrics/headers are non-fatal
        _log.debug("%s: %s", msg, exc)
        return default


PROBE_PATHS = {"/health", "/healthz", "/readyz", "/livez", "/metrics"}

_ID_SAFE = re.compile(r"[^a-zA-Z0-9_.:-]+")


@dataclass(frozen=True)
class RateState:
    quota_day: int
    quota_hour: int
    quota_min: int
    remaining: int
    reset_seconds: int


def _quota_headers(state: RateState) -> Dict[str, str]:
    return {
        "X-Quota-Day": str(max(0, state.quota_day)),
        "X-Quota-Hour": str(max(0, state.quota_hour)),
        "X-Quota-Min": str(max(0, state.quota_min)),
        "X-Quota-Remaining": str(max(0, state.remaining)),
        "X-Quota-Reset": str(max(0, state.reset_seconds)),
    }


def _compute_rate_state(
    limiter: RateLimiter,
    remaining_tokens: float,
    retry_after: Optional[int],
) -> RateState:
    per_min = max(0, int(limiter.refill_rate * 60))
    per_hour = max(0, int(limiter.refill_rate * 3600))
    per_day = max(0, int(limiter.refill_rate * 86400))
    remaining_int = max(0, int(remaining_tokens))
    if retry_after is not None:
        reset_seconds = max(0, int(retry_after))
    else:
        if limiter.refill_rate > 0:
            current = max(0.0, min(float(limiter.capacity), float(remaining_tokens)))
            deficit = max(0.0, float(limiter.capacity) - current)
            reset_seconds = int(math.ceil(deficit / limiter.refill_rate)) if deficit else 0
        else:
            reset_seconds = 0
    return RateState(
        quota_day=per_day,
        quota_hour=per_hour,
        quota_min=per_min,
        remaining=remaining_int,
        reset_seconds=reset_seconds,
    )


def _sanitize(val: str) -> str:
    if not val:
        return "unknown"
    v = _ID_SAFE.sub("_", str(val))[:64]
    return v or "unknown"


def _extract_identity(request: Request) -> Tuple[str, str]:
    h = request.headers
    tenant = (
        h.get("X-Guardrail-Tenant")
        or h.get("X-Tenant")
        or request.query_params.get("tenant")
        or "unknown"
    )
    bot = h.get("X-Guardrail-Bot") or h.get("X-Bot") or request.query_params.get("bot") or "unknown"
    return _sanitize(tenant), _sanitize(bot)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        enabled, limiter = get_global(getattr(request.app.state, "settings", None))
        if not enabled:
            return await call_next(request)

        path = request.url.path
        if path in PROBE_PATHS:
            return await call_next(request)

        tenant, bot = _extract_identity(request)
        enforce_unknown = get_enforce_unknown(getattr(request.app.state, "settings", None))
        if (tenant == "unknown" and bot == "unknown") and not enforce_unknown:
            _best_effort(
                "inc RATE_LIMIT_SKIPS unknown_identity",
                lambda: RATE_LIMIT_SKIPS.labels(reason="unknown_identity").inc(),
            )
            return await call_next(request)

        ok, retry_after, remaining = limiter.allow(tenant, bot, cost=1.0)
        state = _compute_rate_state(limiter, remaining, retry_after)
        if ok:
            response = await call_next(request)

            def _set_headers() -> None:
                limit = f"{limiter.refill_rate:.6g}; burst={limiter.capacity:.6g}"
                response.headers.setdefault("X-RateLimit-Limit", limit)
                response.headers.setdefault("X-RateLimit-Remaining", f"{max(0, int(remaining))}")
                for key, value in _quota_headers(state).items():
                    response.headers.setdefault(key, value)

            _best_effort("set rate limit headers", _set_headers)
            return response

        RATE_LIMIT_BLOCKS.labels(tenant=tenant, bot=bot).inc()
        retry_hdr = str(max(1, int(retry_after or 1)))
        request_id = request.headers.get("X-Request-ID") or get_request_id() or str(uuid.uuid4())
        payload = {
            "detail": "Rate limit exceeded",
            "tenant": tenant,
            "bot": bot,
            "retry_after_seconds": int(retry_hdr),
        }
        if request_id:
            payload["request_id"] = request_id

        # NOTE: Do not emit the generic decision metric here. DecisionHeaderMiddleware
        # will emit exactly one decision metric per request, preventing double counting.
        # We still emit the dedicated rate-limit Prometheus metric elsewhere in this
        # middleware (e.g., guardrail_rate_limited_total{...}).
        def _set_state() -> None:
            request.state.guardrail_decision = {
                "outcome": "block_input_only",
                "mode": "Tier1",
                "incident_id": payload.get("incident_id") or f"rl-{tenant}-{bot}",
            }

        _best_effort("set guardrail_decision state", _set_state)
        return JSONResponse(
            payload,
            status_code=429,
            headers={
                "Retry-After": retry_hdr,
                "X-RateLimit-Limit": f"{limiter.refill_rate:.6g}; burst={limiter.capacity:.6g}",
                "X-RateLimit-Remaining": "0",
                **_quota_headers(state),
                **({"X-Request-ID": request_id} if request_id else {}),
            },
        )
