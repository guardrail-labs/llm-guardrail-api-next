from __future__ import annotations

import re
import uuid
from typing import Tuple

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.middleware.request_id import get_request_id
from app.services.ratelimit import (
    RATE_LIMIT_BLOCKS,
    RATE_LIMIT_SKIPS,
    get_enforce_unknown,
    get_global,
)

PROBE_PATHS = {"/health", "/healthz", "/readyz", "/livez", "/metrics"}

_ID_SAFE = re.compile(r"[^a-zA-Z0-9_.:-]+")


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
    bot = (
        h.get("X-Guardrail-Bot")
        or h.get("X-Bot")
        or request.query_params.get("bot")
        or "unknown"
    )
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
            try:
                RATE_LIMIT_SKIPS.labels(reason="unknown_identity").inc()
            except Exception:
                pass
            return await call_next(request)

        ok, retry_after, remaining = limiter.allow(tenant, bot, cost=1.0)
        if ok:
            response = await call_next(request)
            try:
                limit = f"{limiter.refill_rate:.6g}; burst={limiter.capacity:.6g}"
                response.headers.setdefault("X-RateLimit-Limit", limit)
                response.headers.setdefault("X-RateLimit-Remaining", f"{max(0, int(remaining))}")
            except Exception:
                pass
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
        try:
            request.state.guardrail_decision = {
                "outcome": "block_input_only",
                "mode": "Tier1",
                "incident_id": payload.get("incident_id") or f"rl-{tenant}-{bot}",
            }
        except Exception:
            pass
        return JSONResponse(
            payload,
            status_code=429,
            headers={
                "Retry-After": retry_hdr,
                "X-RateLimit-Limit": f"{limiter.refill_rate:.6g}; burst={limiter.capacity:.6g}",
                "X-RateLimit-Remaining": "0",
                **({"X-Request-ID": request_id} if request_id else {}),
            },
        )
