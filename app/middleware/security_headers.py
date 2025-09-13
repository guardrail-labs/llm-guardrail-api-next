from __future__ import annotations

import os
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


class _SecurityHeaders(BaseHTTPMiddleware):
    """
    Sets basic security headers on all responses.

    Defaults (to satisfy tests):
      - X-Frame-Options: DENY
      - X-Content-Type-Options: nosniff
      - Referrer-Policy: no-referrer  (back-compat with SEC_HEADERS_REFERRER_POLICY)
    """

    def __init__(self, app):
        super().__init__(app)

        # Defaults ON unless explicitly disabled
        xfo_env = os.getenv("SEC_HEADERS_XFO_ENABLED")
        self._xfo_enabled = True if xfo_env is None else _truthy(xfo_env)

        nosniff_env = os.getenv("SEC_HEADERS_NOSNIFF_ENABLED")
        self._nosniff_enabled = True if nosniff_env is None else _truthy(nosniff_env)

        # Back-compat: SEC_HEADERS_REFERRER_POLICY takes precedence if set.
        referrer_val = os.getenv("SEC_HEADERS_REFERRER_POLICY")
        if referrer_val is None:
            # Default expected by tests
            referrer_val = "no-referrer"
        self._referrer_policy = referrer_val

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp = await call_next(request)

        if self._xfo_enabled:
            resp.headers.setdefault("X-Frame-Options", "DENY")

        if self._nosniff_enabled:
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")

        if self._referrer_policy:
            resp.headers.setdefault("Referrer-Policy", self._referrer_policy)

        return resp


def install_security_headers(app) -> None:
    """Wire the middleware (name used by app.main)."""
    app.add_middleware(_SecurityHeaders)


# Optional helper for modules that snapshot config (referenced by logging JSON).
def sec_headers_enabled() -> bool:
    # With our defaults, this feature is effectively enabled unless explicitly disabled.
    xfo_env = os.getenv("SEC_HEADERS_XFO_ENABLED")
    nosniff_env = os.getenv("SEC_HEADERS_NOSNIFF_ENABLED")
    # If either is enabled (or unset -> enabled), return True
    xfo = True if xfo_env is None else _truthy(xfo_env)
    nosniff = True if nosniff_env is None else _truthy(nosniff_env)
    return xfo or nosniff or bool(os.getenv("SEC_HEADERS_REFERRER_POLICY", "no-referrer"))
