# app/middleware/csp.py
# Summary (PR-Y fix): Add optional CSP and Referrer-Policy headers.
# - Disabled by default; enable via env toggles.
# - Does not override headers if an upstream already set them.
# - Env:
#     CSP_ENABLED                 (default: 0)
#     CSP_VALUE                   (default: "default-src 'none'; frame-ancestors 'none';"
#                                  " base-uri 'none'")
#     REFERRER_POLICY_ENABLED     (default: 0)
#     REFERRER_POLICY_VALUE       (default: "no-referrer")

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp  # for mypy-accurate __init__ typing

from app.services.config_sanitizer import get_bool


def _get_str(name: str, default: str) -> str:
    val = os.getenv(name)
    if val is None:
        return default
    v = val.strip()
    return v if v else default


class _CSPMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        csp: Optional[str],
        referrer_policy: Optional[str],
    ) -> None:
        super().__init__(app)
        self._csp = csp
        self._rp = referrer_policy

    async def dispatch(
        self, request: StarletteRequest, call_next
    ) -> StarletteResponse:
        resp: StarletteResponse = await call_next(request)

        # Do not override if already present
        if self._csp and "content-security-policy" not in {
            k.lower(): v for k, v in resp.headers.items()
        }:
            resp.headers["Content-Security-Policy"] = self._csp

        if self._rp and "referrer-policy" not in {
            k.lower(): v for k, v in resp.headers.items()
        }:
            resp.headers["Referrer-Policy"] = self._rp

        return resp


def install_csp(app: FastAPI) -> None:
    csp_enabled = get_bool("CSP_ENABLED", False)
    rp_enabled = get_bool("REFERRER_POLICY_ENABLED", False)

    if not (csp_enabled or rp_enabled):
        return

    csp_val = (
        _get_str(
            "CSP_VALUE",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        if csp_enabled
        else None
    )
    rp_val = _get_str("REFERRER_POLICY_VALUE", "no-referrer") if rp_enabled else None

    app.add_middleware(_CSPMiddleware, csp=csp_val, referrer_policy=rp_val)
