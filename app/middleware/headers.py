from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to all responses."""

    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        hdrs = resp.headers
        hdrs.setdefault("X-Content-Type-Options", "nosniff")
        hdrs.setdefault("X-Frame-Options", "DENY")
        hdrs.setdefault("Referrer-Policy", "no-referrer")
        # HSTS (enable only when serving behind TLS in prod)
        # hdrs.setdefault(
        #     "Strict-Transport-Security",
        #     "max-age=31536000; includeSubDomains",
        # )
        return resp
