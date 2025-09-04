from __future__ import annotations

import hashlib
import logging
import os
import uuid
from math import ceil
from typing import Optional

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.services.rate_limit import TokenBucket

logger = logging.getLogger(__name__)


def inc_rate_limited(by: float = 1.0) -> None:
    try:
        return
    except Exception as exc:  # pragma: no cover
        logger.warning("inc_rate_limited failed: %s", exc)


def _get_trace_id() -> str:
    return uuid.uuid4().hex


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_limits_from_env():
    enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    legacy = "RATE_LIMIT_PER_MINUTE" in os.environ or "RATE_LIMIT_BURST" in os.environ
    if legacy:
        per_min = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        burst = int(os.getenv("RATE_LIMIT_BURST", str(per_min)))
        return enabled, per_min, burst, per_min, per_min, True

    per_key = int(os.getenv("RATE_LIMIT_PER_API_KEY_PER_MIN", "60"))
    per_ip = int(os.getenv("RATE_LIMIT_PER_IP_PER_MIN", "120"))
    return enabled, per_key, per_key, per_key, per_ip, False


class RateLimitMiddleware:
    """ASGI middleware for per-key and per-IP token-bucket rate limiting."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: Optional[bool] = None,
        per_api_key_per_min: Optional[int] = None,
        per_ip_per_min: Optional[int] = None,
        burst: Optional[int] = None,
    ) -> None:
        self.app = app

        (
            env_enabled,
            env_per_min,
            env_burst,
            env_key_min,
            env_ip_min,
            legacy_unified,
        ) = _parse_limits_from_env()
        self.enabled = env_enabled if enabled is None else enabled
        self.legacy_unified = legacy_unified

        per_key = env_key_min if per_api_key_per_min is None else per_api_key_per_min
        per_ip = env_ip_min if per_ip_per_min is None else per_ip_per_min

        key_capacity = burst if burst is not None else per_key
        ip_capacity = burst if burst is not None else per_ip

        self.key_bucket = TokenBucket(capacity=key_capacity, refill_per_sec=per_key / 60.0)
        self.ip_bucket = TokenBucket(capacity=ip_capacity, refill_per_sec=per_ip / 60.0)

        self.generic_limit_per_min = env_per_min
        self.per_key_per_min = per_key
        self.per_ip_per_min = per_ip
        self.key_capacity = key_capacity
        self.ip_capacity = ip_capacity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        headers = dict((k.decode().lower(), v.decode()) for k, v in scope.get("headers", []))
        api_key_raw = headers.get("x-api-key") or _parse_bearer(headers.get("authorization") or "")
        ip = _client_ip(headers, scope) or "0.0.0.0"

        api_key_hash = _hash(api_key_raw) if api_key_raw else "anon"
        ip_hash = _hash(ip)

        allow_key = self.key_bucket.allow(api_key_hash)
        allow_ip = self.ip_bucket.allow(ip_hash)

        if allow_key and allow_ip:
            async def send_wrapped(message: Message) -> None:
                if message.get("type") == "http.response.start":
                    self._attach_allowed_headers(message, api_key_hash, ip_hash)
                await send(message)

            await self.app(scope, receive, send_wrapped)
            return

        wait_key = 0.0 if allow_key else self.key_bucket.estimate_wait_seconds(api_key_hash)
        wait_ip = 0.0 if allow_ip else self.ip_bucket.estimate_wait_seconds(ip_hash)
        retry_after = 60 if self.legacy_unified else int(max(wait_key, wait_ip))

        try:
            inc_rate_limited(1.0)
        except Exception as exc:  # pragma: no cover
            logger.warning("inc_rate_limited failed: %s", exc)

        request_id = _get_trace_id()
        payload = {
            "code": "rate_limited",
            "detail": "rate limit exceeded",
            "action": "blocked_escalated",
            "mode": "rate_limited",
            "message": "Too many requests. Please retry later.",
            "retry_after_seconds": retry_after,
            "request_id": request_id,
            "trace_id": request_id,
        }
        resp = JSONResponse(payload, status_code=429)
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = str(self.generic_limit_per_min)
        resp.headers["X-RateLimit-Remaining"] = "0"
        resp.headers["X-RateLimit-Reset"] = str(max(1, retry_after))
        resp.headers["X-RateLimit-Blocked"] = "api_key" if not allow_key else "ip"
        resp.headers.setdefault("X-Trace-ID", request_id)
        resp.headers.setdefault("X-Request-ID", request_id)
        await resp(scope, receive, send)

    # ---------------------- internals ----------------------

    def _attach_allowed_headers(self, message: Message, api_key_hash: str, ip_hash: str) -> None:
        headers = message.setdefault("headers", [])
        # Generic
        headers.append((b"X-RateLimit-Limit", str(self.generic_limit_per_min).encode()))
        rem_key = self.key_bucket.remaining(api_key_hash)
        rem_ip = self.ip_bucket.remaining(ip_hash)
        remaining_float = min(rem_key, rem_ip)
        remaining_int = max(0, int(remaining_float))
        headers.append((b"X-RateLimit-Remaining", str(remaining_int).encode()))
        to_full_key = (self.key_capacity - rem_key) / max(1e-9, self.per_key_per_min / 60.0)
        to_full_ip = (self.ip_capacity - rem_ip) / max(1e-9, self.per_ip_per_min / 60.0)
        reset_sec = max(1, int(ceil(min(to_full_key, to_full_ip))))
        headers.append((b"X-RateLimit-Reset", str(reset_sec).encode()))
        # Dimension-specific extras
        headers.append((b"X-RateLimit-Limit-ApiKey", str(self.key_capacity).encode()))
        headers.append((b"X-RateLimit-Remaining-ApiKey", f"{rem_key:.2f}".encode()))
        headers.append((b"X-RateLimit-Limit-IP", str(self.ip_capacity).encode()))
        headers.append((b"X-RateLimit-Remaining-IP", f"{rem_ip:.2f}".encode()))


def _parse_bearer(auth_header: str) -> str:
    parts = (auth_header or "").split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _client_ip(headers: dict, scope: Scope) -> str:
    xff = headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else ""
