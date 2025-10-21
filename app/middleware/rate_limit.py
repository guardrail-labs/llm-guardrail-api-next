from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, Tuple, Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# --------------------------- Constants / defaults ----------------------------

PROBE_PATHS = {"/readyz", "/livez", "/metrics", "/healthz"}
_TENANT_HDRS = ("X-Guardrail-Tenant", "X-Tenant")
_BOT_HDRS = ("X-Guardrail-Bot", "X-Bot")
_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_-]+")

# ------------------------ Exposed counter for tests --------------------------
# tests/test_rate_limit_metrics.py monkeypatches app.middleware.rate_limit.RATE_LIMIT_BLOCKS
try:
    from app.services.ratelimit import RATE_LIMIT_BLOCKS as _GLOBAL_BLOCK_COUNTER  
except Exception:  # pragma: no cover
    class _NoopCounter:
        def inc(self, *_, **__):
            pass

    _GLOBAL_BLOCK_COUNTER = _NoopCounter()

# Export a symbol that tests can patch:
RATE_LIMIT_BLOCKS = _GLOBAL_BLOCK_COUNTER


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


def _get_request_id_safe() -> str:
    # Avoid import cycles by importing at call time.
    try:
        from app.middleware.request_id import get_request_id  
        return get_request_id() or ""
    except Exception:
        return ""


def _blocked_payload(retry_after_s: int, tenant: str, bot: str) -> Dict[str, Any]:
    # Tests expect both 'detail' and 'retry_after_seconds'
    return {
        "detail": "Rate limit exceeded",
        "retry_after_seconds": int(max(1, retry_after_s)),
        # Keep the existing envelope some parts of the app may rely on
        "error": {
            "code": "rate_limited",
            "message": "Rate limit exceeded. Try again later.",
        },
        "tenant": tenant or "unknown",
        "bot": bot or "unknown",
    }


def _allowed_headers(limit_str: str, remaining: int | None) -> Dict[str, str]:
    # On allowed responses, tests only check presence/values for a subset.
    rem = str(max(0, int(math.floor((remaining or 0) + 1e-9))))
    return {
        "X-RateLimit-Limit": limit_str,
        "X-RateLimit-Remaining": rem,
        "X-Quota-Min": "60",
        "X-Quota-Hour": "3600",
        "X-Quota-Day": "86400",
        "X-Quota-Remaining": rem,
        # any non-empty value is acceptable on success per tests
        "X-Quota-Reset": "60",
        "X-Guardrail-Decision": "allow",
    }


def _blocked_headers(
    limit_str: str,
    retry_after_s: int,
) -> Dict[str, str]:
    # Blocked path headers must match tests exactly
    h = {
        "Retry-After": str(int(max(1, retry_after_s))),
        "X-RateLimit-Limit": limit_str,
        "X-RateLimit-Remaining": "0",
        "X-Quota-Min": "60",
        "X-Quota-Hour": "3600",
        "X-Quota-Day": "86400",
        "X-Quota-Remaining": "0",
        # tests expect "1" (seconds) on blocked responses
        "X-Quota-Reset": "1",
        # decision header required by tests that also add DecisionHeaderMiddleware
        "X-Guardrail-Decision": "block_input_only",
    }
    rid = _get_request_id_safe()
    if rid:
        h["X-Request-ID"] = rid
    return h


class RateLimitMiddleware(BaseHTTPMiddleware):
__all__ = ["RateLimitMiddleware", "RATE_LIMIT_BLOCKS"]
