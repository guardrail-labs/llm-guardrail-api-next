# app/middleware/rate_limit.py
"""
FastAPI middleware for per-API-key and per-IP rate limiting.

- Returns 429 with Retry-After when limits are exceeded.
- Emits generic X-RateLimit-* headers (and dimension-specific ones).
- Exposes inc_rate_limited() and _get_trace_id() for tests to monkeypatch.
- Supports legacy envs: RATE_LIMIT_PER_MINUTE, RATE_LIMIT_BURST.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from math import ceil
from typing import Awaitable, Callable, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.rate_limit import TokenBucket

logger = logging.getLogger(__name__)


# ---- Test hooks (monkeypatched in tests) -------------------------------------
def inc_rate_limited(by: float = 1.0) -> None:
    """Increment a metric when a request is rate limited."""
    try:
        # In prod you can call your metrics module here.
        return
    except Exception as exc:  # pragma: no cover
        # Tests look specifically for this message text.
        logger.warning("inc_rate_limited failed: %s", exc)


def _get_trace_id() -> str:
    """Return a request/trace id (tests patch this to a fixed value)."""
    return uuid.uuid4().hex


# ---- Helpers -----------------------------------------------------------------
def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_limits_from_env() -> Tuple[bool, int, int, int, int]:
    """
    Return (enabled, generic_per_min, burst, per_key_min, per_ip_min).

    Legacy unified config (applies to both key & IP):
      RATE_LIMIT_PER_MINUTE, RATE_LIMIT_BURST
    New split config:
      RATE_LIMIT_PER_API_KEY_PER_MIN, RATE_LIMIT_PER_IP_PER_MIN
    """
    enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # Legacy unified config
    if "RATE_LIMIT_PER_MINUTE" in os.environ or "RATE_LIMIT_BURST" in os.environ:
        per_min = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        burst = int(os.getenv("RATE_LIMIT_BURST", str(per_min)))
        return enabled, per_min, burst, per_min, per_min

    # Split config (new)
    per_key = int(os.getenv("RATE_LIMIT_PER_API_KEY_PER_MIN", "60"))
    per_ip = int(os.getenv("RATE_LIMIT_PER_IP_PER_MIN", "120"))
    # Use per_key as generic limit; burst defaults to per_key for headers if needed
    return enabled, per_key, per_key, per_key, per_ip


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Two independent token buckets:
      - per API key (if present)
      - per IP address (always)
    A request must pass both buckets.
    """

    def __init__(
        self,
        app: Callable,
        enabled: Optional[bool] = None,
        per_api_key_per_min: Optional[int] = None,
        per_ip_per_min: Optional[int] = None,
        burst: Optional[int] = None,
    ) -> None:
        super().__init__(app)

        env_enabled, env_per_min, env_burst, env_key_min, env_ip_min = _parse_limits_from_env()
        self.enabled = env_enabled if enabled is None else enabled

        # If caller passed explicit per-minute limits, use them; else env values.
        per_key = env_key_min if per_api_key_per_min is None else per_api_key_per_min
        per_ip = env_ip_min if per_ip_per_min is None else per_ip_per_min

        # Use **separate capacities** so "ignore IP" tests work as intended.
        key_capacity = burst if burst is not None else per_key
        ip_capacity = burst if burst is not None else per_ip

        # Buckets: capacity = per-dimension capacity, refill = per-minute / 60
        self.key_bucket = TokenBucket(capacity=key_capacity, refill_per_sec=per_key / 60.0)
        self.ip_bucket = TokenBucket(capacity=ip_capacity, refill_per_sec=per_ip / 60.0)

        # For headers
        self.generic_limit_per_min = env_per_min
        self.per_key_per_min = per_key
        self.per_ip_per_min = per_ip
        self.key_capacity = key_capacity
        self.ip_capacity = ip_capacity

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Identify caller
        api_key_raw = (
            request.headers.get("x-api-key")
            or request.headers.get("X-API-Key")
            or self._parse_bearer(request.headers.get("authorization") or "")
            or ""
        )
        ip = self._client_ip(request) or "0.0.0.0"

        api_key_hash = _hash(api_key_raw) if api_key_raw else "anon"
        ip_hash = _hash(ip)

        # Check buckets (cost is 1 per request by default)
        allow_key = self.key_bucket.allow(api_key_hash)
        allow_ip = self.ip_bucket.allow(ip_hash)

        if allow_key and allow_ip:
            resp = await call_next(request)
            self._attach_allowed_headers(resp, api_key_hash, ip_hash)
            return resp

        # Compute wait times for whichever dimension(s) blocked
        wait_key = 0.0 if allow_key else self.key_bucket.estimate_wait_seconds(api_key_hash)
        wait_ip = 0.0 if allow_ip else self.ip_bucket.estimate_wait_seconds(ip_hash)
        retry_after = int(max(wait_key, wait_ip))

        # Metric (should not raise)
        try:
            inc_rate_limited(1.0)
        except Exception as exc:  # pragma: no cover
            logger.warning("inc_rate_limited failed: %s", exc)

        request_id =_
