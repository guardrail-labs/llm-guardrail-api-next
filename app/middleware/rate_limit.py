from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# --------------------------- Constants / defaults ----------------------------

PROBE_PATHS = {"/readyz", "/livez", "/metrics", "/healthz"}
_TENANT_HDRS = ("X-Guardrail-Tenant", "X-Tenant")
_BOT_HDRS = ("X-Guardrail-Bot", "X-Bot")
_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_-]+")


# ------------------------------- Helpers ------------------------------------


def _sanitize(value: str) -> str:
    return _SANITIZE_RE.sub("_", value) if value else "unknown"


def _now() -> float:
    return time.monotonic()


def _extract_identity(request: Request) -> Tuple[str, str]:
    headers = request.headers
    tenant = next((headers.get(h, "") for h in _TENANT_HDRS if headers.get(h)), "")
    bot = next((headers.get(h, "") for h in _BOT_HDRS if headers.get(h)), "")
    return _sanitize(tenant), _sanitize(bot)


def _format_limit(rps: float, burst: float | int) -> str:
    rate = f"{int(rps)}" if float(rps).is_integer() else f"{rps}"
    return f"{rate}; burst={int(burst)}"


# ----------------------------- Middleware ------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token-bucket rate limiter integrated with app.services.ratelimit."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in PROBE_PATHS:
            return await call_next(request)

        try:
            from app.services import ratelimit as RL  # lazy import
        except Exception:
            return await call_next(request)

        app_settings: Any = getattr(request.app.state, "settings", None)
        enabled, limiter = RL.get_global(app_settings)
        if not enabled:
            return await call_next(request)

        tenant, bot = _extract_identity(request)
        enforce_unknown = RL.get_enforce_unknown(app_settings)

        if (tenant == "unknown" and bot == "unknown") and not enforce_unknown:
            try:
                RL.RATE_LIMIT_SKIPS.labels(reason="unknown_identity").inc()
            except Exception:
                pass
            return await call_next(request)

        allowed, retry_after_s, remaining = limiter.allow(tenant, bot, cost=1.0)
        rps = float(limiter.refill_rate)
        burst = float(limiter.capacity)

        quota_headers: Dict[str, str] = {
            "X-RateLimit-Limit": _format_limit(rps, burst),
            "X-RateLimit-Remaining": str(max(0, int(math.floor(remaining + 1e-9)))),
            "X-Quota-Min": str(int(rps * 60)),
            "X-Quota-Hour": str(int(rps * 3600)),
            "X-Quota-Day": str(int(rps * 86400)),
            "X-Quota-Remaining": str(
                max(0, int(math.floor(remaining + 1e-9)))
            )
            if remaining is not None
            else "0",
            "X-Quota-Reset": str(
                int(_now()) + (retry_after_s if retry_after_s is not None else 0)
            ),
        }

        if allowed:
            resp = await call_next(request)
            for key, val in quota_headers.items():
                resp.headers.setdefault(key, val)
            return resp

        try:
            RL.RATE_LIMIT_BLOCKS.labels(tenant=tenant, bot=bot).inc()
        except Exception:
            pass

        retry_after_val = max(1, int(retry_after_s or 1))
        headers = {"Retry-After": str(retry_after_val)}
        headers.update(quota_headers)

        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "rate_limited",
                    "message": "Rate limit exceeded. Try again later.",
                },
                "tenant": tenant,
                "bot": bot,
            },
            headers=headers,
        )
