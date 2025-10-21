from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# ---- Constants / defaults ----------------------------------------------------

# Probe endpoints must bypass rate limiting.
PROBE_PATHS = {"/readyz", "/livez", "/metrics", "/healthz"}

# Identity headers (tests exercise both "Guardrail-" and plain variants).
_TENANT_HDRS = ("X-Guardrail-Tenant", "X-Tenant")
_BOT_HDRS = ("X-Guardrail-Bot", "X-Bot")

_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _sanitize(s: str) -> str:
    return _SANITIZE_RE.sub("_", s) if s else "unknown"


def _now() -> float:
    # Separate indirection so tests can control the monotonic clock via the
    # services.ratelimit backend without touching this module.
    return time.monotonic()


def _extract_identity(request: Request) -> Tuple[str, str]:
    headers = request.headers
    tenant = next((headers.get(h, "") or "" for h in _TENANT_HDRS), "")
    bot = next((headers.get(h, "") or "" for h in _BOT_HDRS), "")
    return _sanitize(tenant), _sanitize(bot)


def _format_limit(rps: float, burst: float | int) -> str:
    # Tests expect integers to be rendered as whole numbers, e.g. "1; burst=1".
    limit_str = f"{int(rps)}" if float(rps).is_integer() else f"{rps}"
    return f"{limit_str}; burst={int(burst)}"


# ------------------------------- Middleware ----------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket rate limiter.

    Behaviors required by tests:
      - Bypass probe paths (/readyz, /livez, /metrics, /healthz)
      - Respect per-app settings at `app.state.settings.ingress.rate_limit`
        with env var fallbacks handled by app.services.ratelimit
      - If both tenant and bot identities are "unknown", bypass by default
        unless RATE_LIMIT_ENFORCE_UNKNOWN=true (or settings override)
      - Emit X-RateLimit-* and X-Quota-* headers on both allow and deny
      - On deny, return 429 JSON with {"error": {"code": "rate_limited", ...}}
        plus Retry-After header
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Fast bypass for probes.
        if request.url.path in PROBE_PATHS:
            return await call_next(request)

        # Build/get limiter from the canonical service (which the tests monkeypatch).
        # We pass through app.state.settings so tests can override rps/burst/enabled.
        try:
            from app.services import ratelimit as RL  # lazy to avoid import cycles
        except Exception:
            # If the service is unavailable, just allow the request.
            return await call_next(request)

        enabled, limiter = RL.get_global(getattr(request.app.state, "settings", None))
        if not enabled:
            return await call_next(request)

        tenant, bot = _extract_identity(request)

        # "Unknown" bypass unless configured to enforce.
        enforce_unknown = RL.get_enforce_unknown(getattr(request.app.state, "settings", None))
        if (tenant == "unknown" and bot == "unknown") and not enforce_unknown:
            try:
                RL.RATE_LIMIT_SKIPS.labels(reason="unknown_identity").inc()
            except Exception:
                pass
            return await call_next(request)

        # Evaluate allowance (services layer exposes retry_after as int|None and remaining float).
        allowed, retry_after_s, remaining = limiter.allow(tenant, bot, cost=1.0)

        # Header set (present both on allow & deny).
        rps = float(limiter.refill_rate)
        burst = float(limiter.capacity)

        quota_headers: Dict[str, str] = {
            "X-RateLimit-Limit": _format_limit(rps, burst),
            "X-RateLimit-Remaining": str(max(0, int(math.floor(remaining + 1e-9)))),
            # Convenience "quota" headers (per minute/hour/day) plus remaining/reset.
            "X-Quota-Min": str(int(rps * 60)),
            "X-Quota-Hour": str(int(rps * 3600)),
            "X-Quota-Day": str(int(rps * 86400)),
            "X-Quota-Remaining": str(max(0, int(math.floor(remaining + 1e-9)))) if remaining is not None else "0",
            "X-Quota-Reset": str(int(_now()) + (retry_after_s if retry_after_s is not None else 0)),
        }

        if allowed:
            resp = await call_next(request)
            for k, v in quota_headers.items():
                # Only set if missing to avoid clobbering explicit handler values.
                resp.headers.setdefault(k, v)
            return resp

        # On deny: record the block metric and return 429 with Retry-After.
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
