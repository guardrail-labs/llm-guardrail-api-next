from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to all responses."""

    def __init__(self, app) -> None:
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        if self.settings.SECURITY_HEADERS_ENABLED:
            hdrs = resp.headers
            hdrs.setdefault("X-Content-Type-Options", "nosniff")
            hdrs.setdefault("X-Frame-Options", "DENY")
            hdrs.setdefault("X-XSS-Protection", "0")
            hdrs.setdefault("Referrer-Policy", "no-referrer")
            if self.settings.ADD_COOP:
                hdrs.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            if self.settings.ADD_PERMISSIONS_POLICY:
                hdrs.setdefault("Permissions-Policy", "interest-cohort=()")
        return resp
