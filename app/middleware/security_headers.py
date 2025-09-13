# app/middleware/security_headers.py
# Summary (PR-Y compat/fix v2): Security headers middleware with sane defaults.
# - Defaults: X-Frame-Options=DENY, X-Content-Type-Options=nosniff,
#             Referrer-Policy=no-referrer, Permissions-Policy=geolocation=()
# - Legacy env SEC_HEADERS_REFERRER_POLICY still supported (overrides default).
# - Uses .setdefault so upstream headers aren't overwritten.
# - Exposes sec_headers_enabled() for other modules (e.g., JSON logging).

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp


def _get_bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    s = val.strip().lower()
    return s in {"1", "true", "yes", "on"}


def _get_str(name: str) -> Optional[str]:
    val = os.getenv(name)
    if val is None:
        return None
    s = val.strip()
    return s or None


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        xfo_enabled: bool,
        nosniff_enabled: bool,
        referrer_policy: Optional[str],
        permissions_policy: Optional[str],
    ) -> None:
        super().__init__(app)
        self._xfo = xfo_enabled
        self._nosniff = nosniff_enabled
        self._referrer = referrer_policy
        self._perm = permissions_policy

    async def dispatch(
        self, request: StarletteRequest, call_next
    ) -> StarletteResponse:
        resp: StarletteResponse = await call_next(request)

        if self._xfo:
            resp.headers.setdefault("X-Frame-Options", "DENY")
        if self._nosniff:
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        if self._referrer:
            resp.headers.setdefault("Referrer-Policy", self._referrer)
        if self._perm:
            resp.headers.setdefault("Permissions-Policy", self._perm)

        return resp


def install_security_headers(app: FastAPI) -> None:
    """
    Install a lightweight security-headers middleware.

    Defaults:
    - X-Frame-Options, X-Content-Type-Options are enabled by default.
    - Referrer-Policy defaults to "no-referrer" (legacy behavior).
    - Permissions-Policy defaults to "geolocation=()" (safe baseline).
    Overrides:
    - SEC_HEADERS_REFERRER_POLICY overrides the default referrer policy if set.
    - SEC_HEADERS_PERMISSIONS_POLICY overrides the default permissions policy if set.
    - SEC_HEADERS_XFO_ENABLED / SEC_HEADERS_NOSNIFF_ENABLED can disable those headers.
    """
    xfo_enabled = _get_bool_env("SEC_HEADERS_XFO_ENABLED", True)
    nosniff_enabled = _get_bool_env("SEC_HEADERS_NOSNIFF_ENABLED", True)

    # Defaults with legacy override capability
    referrer_policy = _get_str("SEC_HEADERS_REFERRER_POLICY") or "no-referrer"
    permissions_policy = _get_str("SEC_HEADERS_PERMISSIONS_POLICY") or "geolocation=()"

    # If everything disabled AND both optional strings empty, skip.
    if not (xfo_enabled or nosniff_enabled or referrer_policy or permissions_policy):
        return

    app.add_middleware(
        _SecurityHeadersMiddleware,
        xfo_enabled=xfo_enabled,
        nosniff_enabled=nosniff_enabled,
        referrer_policy=referrer_policy,
        permissions_policy=permissions_policy,
    )


def sec_headers_enabled() -> bool:
    """
    Helper used by other modules to check if this middleware would emit headers
    given current env (defaults count as enabled).
    """
    return any(
        [
            _get_bool_env("SEC_HEADERS_XFO_ENABLED", True),
            _get_bool_env("SEC_HEADERS_NOSNIFF_ENABLED", True),
            True,  # Referrer-Policy defaults on
            True,  # Permissions-Policy defaults on
        ]
    )
