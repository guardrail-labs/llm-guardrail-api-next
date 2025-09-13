from __future__ import annotations

import os
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.middleware.env import get_bool

_DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


class _CSPMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, csp: str | None, referrer_policy: str | None):
        super().__init__(app)
        self._csp = csp
        self._rp = referrer_policy

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        resp = await call_next(request)
        if self._csp:
            resp.headers.setdefault("content-security-policy", self._csp)
        if self._rp:
            resp.headers.setdefault("referrer-policy", self._rp)
        return resp


def install_csp(app) -> None:
    if not get_bool("CSP_ENABLED"):
        return
    csp_val = (os.getenv("CSP_VALUE") or _DEFAULT_CSP).strip()
    rp_val = (os.getenv("REFERRER_POLICY_VALUE") or "no-referrer").strip() \
        if get_bool("REFERRER_POLICY_ENABLED") else None
    app.add_middleware(_CSPMiddleware, csp=csp_val, referrer_policy=rp_val)

