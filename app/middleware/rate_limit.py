"""
FastAPI middleware for per-API-key and per-IP rate limiting.

- Returns 429 with Retry-After when limits exceeded.
- Emits helpful headers for observability.
"""

from __future__ import annotations

import hashlib
import os
from typing import Awaitable, Callable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.rate_limit import TokenBucket


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_limits_from_env() -> tuple[bool, int, int]:
    enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    per_key = int(os.getenv("RATE_LIMIT_PER_API_KEY_PER_MIN", "60"))
    per_ip = int(os.getenv("RATE_LIMIT_PER_IP_PER_MIN", "120"))
    return enabled, per_key, per_ip


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
    ) -> None:
        super().__init__(app)
        env_enabled, env_key, env_ip = _parse_limits_from_env()
        self.enabled = env_enabled if enabled is None else enabled

        key_cap = env_key if per_api_key_per_min is None else per_api_key_per_min
        ip_cap = env_ip if per_ip_per_min is None else per_ip_per_min

        # Convert per-minute capacities into per-second refill rates
        self.key_bucket = TokenBucket(capacity=key_cap, refill_per_sec=key_cap / 60.0)
        self.ip_bucket = TokenBucket(capacity=ip_cap, refill_per_sec=ip_cap / 60.0)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Identify caller
        api_key_raw = (
            request.headers.get("x-api-key")
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
            # Add helpful headers
            resp.headers["X-RateLimit-Limit-ApiKey"] = str(self.key_bucket.capacity)
            resp.headers["X-RateLimit-Remaining-ApiKey"] = (
                f"{self.key_bucket.remaining(api_key_hash):.2f}"
            )
            resp.headers["X-RateLimit-Limit-IP"] = str(self.ip_bucket.capacity)
            resp.headers["X-RateLimit-Remaining-IP"] = (
                f"{self.ip_bucket.remaining(ip_hash):.2f}"
            )
            return resp

        # Compute wait times for whichever dimension(s) blocked
        wait_key = (
            0.0
            if allow_key
            else self.key_bucket.estimate_wait_seconds(api_key_hash)
        )
        wait_ip = (
            0.0
            if allow_ip
            else self.ip_bucket.estimate_wait_seconds(ip_hash)
        )
        retry_after = int(max(wait_key, wait_ip))

        payload = {
            "action": "blocked_escalated",
            "mode": "rate_limited",
            "message": "Too many requests. Please retry later.",
            "retry_after_seconds": retry_after,
        }
        resp = JSONResponse(payload, status_code=429)
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Blocked"] = "api_key" if not allow_key else "ip"
        return resp

    @staticmethod
    def _parse_bearer(auth_header: str) -> str:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return ""

    @staticmethod
    def _client_ip(request: Request) -> str:
        # Honor common proxy headers if present (still hashed before storage)
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # first IP in the list is the original client
            return xff.split(",")[0].strip()
        return request.client.host if request.client else ""

