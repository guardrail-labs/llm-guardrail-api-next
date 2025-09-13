# app/middleware/security_headers.py
# Summary (PR-Y compat): Restore Referrer-Policy via legacy env.
# - Keeps existing security headers behavior.
# - Honors legacy env var SEC_HEADERS_REFERRER_POLICY to preserve backward
#   compatibility (sets Referrer-Policy when present).
# - Uses .setdefault() so it never overwrites headers set upstream or by other
#   middlewares (e.g., CSP/referrer module).
# - Mypy/ruff clean: typed BaseHTTPMiddleware and ASGIApp signatures.

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp

from app.services.config_sanitizer import get_bool


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

    Back-compat:
    - If SEC_HEADERS_REFERRER_POLICY is set (e.g., "no-referrer"), we emit
      Referrer-Policy with that exact value.
    """
    xfo_enabled = get_bool("SEC_HEADERS_XFO_ENABLED", True)
    nosniff_enabled = get_bool("SEC_HEADERS_NOSNIFF_ENABLED", True)

    # Backward-compat alias: preserve previous deployments/tests
    referrer_policy = _get_str("SEC_HEADERS_REFERRER_POLICY")

    # Optional permissions policy (legacy name retained if already used)
    permissions_policy = _get_str("SEC_HEADERS_PERMISSIONS_POLICY")

    # If nothing is enabled or configured, skip installing.
    if not (xfo_enabled or nosniff_enabled or referrer_policy or permissions_policy):
        return

    app.add_middleware(
        _SecurityHeadersMiddleware,
        xfo_enabled=xfo_enabled,
        nosniff_enabled=nosniff_enabled,
        referrer_policy=referrer_policy,
        permissions_policy=permissions_policy,
    )
