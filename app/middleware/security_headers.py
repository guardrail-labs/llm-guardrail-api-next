# app/middleware/security_headers.py
# Summary (PR-Y compat/fix): Security headers middleware with legacy env support.
# - Restores Referrer-Policy via SEC_HEADERS_REFERRER_POLICY for back-compat.
# - Defaults keep X-Frame-Options and X-Content-Type-Options enabled.
# - Adds helper sec_headers_enabled() for other modules (e.g., logging) to query.
# - Removes dependency on get_bool to avoid mypy "too many args" issues.

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

    Back-compat:
    - If SEC_HEADERS_REFERRER_POLICY is set (e.g., "no-referrer"), we emit
      Referrer-Policy with that exact value.
    """
    xfo_enabled = _get_bool_env("SEC_HEADERS_XFO_ENABLED", True)
    nosniff_enabled = _get_bool_env("SEC_HEADERS_NOSNIFF_ENABLED", True)

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


def sec_headers_enabled() -> bool:
    """
    Public helper used by other modules (e.g., JSON logging) to know if the
    security-headers middleware would be active given current env.
    """
    return any(
        [
            _get_bool_env("SEC_HEADERS_XFO_ENABLED", True),
            _get_bool_env("SEC_HEADERS_NOSNIFF_ENABLED", True),
            _get_str("SEC_HEADERS_REFERRER_POLICY") is not None,
            _get_str("SEC_HEADERS_PERMISSIONS_POLICY") is not None,
        ]
    )
