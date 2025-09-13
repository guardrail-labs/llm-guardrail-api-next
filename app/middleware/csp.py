"""
Content Security Policy middleware.

Env (evaluated at request time):
- CSP_ENABLED: 1/true/on to emit header
- CSP_VALUE: policy string; default is a restrictive baseline
- REFERRER_POLICY_ENABLED: if truthy, also emit 'referrer-policy'
- REFERRER_POLICY_VALUE: defaults to 'no-referrer'
"""

from __future__ import annotations

import os
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


_DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


class _CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp: Response = await call_next(request)

        if _truthy(os.getenv("CSP_ENABLED", "0")):
            csp_val = os.getenv("CSP_VALUE", _DEFAULT_CSP)
            resp.headers.setdefault("content-security-policy", csp_val)

        if _truthy(os.getenv("REFERRER_POLICY_ENABLED", "0")):
            rp_val = os.getenv("REFERRER_POLICY_VALUE", "no-referrer")
            resp.headers.setdefault("referrer-policy", rp_val)

        return resp


def install_csp(app) -> None:
    app.add_middleware(_CSPMiddleware)
