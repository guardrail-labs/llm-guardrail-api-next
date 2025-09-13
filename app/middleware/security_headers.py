"""
Security headers middleware (always-on defaults + env overrides).

- Always sets:
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Referrer-Policy: defaults to "no-referrer" (back-compat)
- Optional extras via env:
  - SEC_HEADERS_REFERRER_POLICY   -> overrides default referrer policy
  - SEC_HEADERS_PERMISSIONS_POLICY (e.g., "geolocation=()")
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def _get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[..., Response]) -> Response:
        resp = await call_next(request)

        # Always-on headers
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")

        # Back-compat default for Referrer-Policy, overridable via env
        referrer = _get_env("SEC_HEADERS_REFERRER_POLICY", "no-referrer")
        if referrer:
            resp.headers.setdefault("Referrer-Policy", referrer)

        # Optional Permissions-Policy
        perm = _get_env("SEC_HEADERS_PERMISSIONS_POLICY", "geolocation=()")
        if perm:
            resp.headers.setdefault("Permissions-Policy", perm)

        return resp


def install_security_headers(app) -> None:
    app.add_middleware(_SecurityHeadersMiddleware)


# Small helper used by logging to report status
def sec_headers_enabled() -> bool:
    return True
