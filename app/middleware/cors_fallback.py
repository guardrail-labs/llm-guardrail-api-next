# app/middleware/cors_fallback.py
# Summary (PR-K fallback):
# - Lightweight CORS fallback to guarantee preflight success and ACAO echo.
# - Active only when CORS_ENABLED=1 (matches test toggles).
# - Also ensures X-Content-Type-Options: nosniff is present on all responses.
#
# Behavior:
# - OPTIONS with Origin -> 204 + ACAO/ACAM/ACAH/ACMA headers.
# - Non-OPTIONS with Origin -> adds ACAO (echo) when header not already set.
# - Safe to coexist with CORSMiddleware; we only add headers if missing.
# - Mypy fix: type the request handler so Response isn't inferred as Any.

from __future__ import annotations

import os
from typing import Awaitable, Callable, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

RequestHandler = Callable[[Request], Awaitable[Response]]


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


def _methods_env() -> List[str]:
    vals = _csv_env("CORS_ALLOW_METHODS")
    return [m.upper() for m in vals] if vals else ["GET", "POST", "OPTIONS"]


def _max_age() -> int:
    raw = os.getenv("CORS_MAX_AGE")
    if not raw:
        return 600
    try:
        v = int(float(raw.strip()))
        return v if v >= 0 else 600
    except Exception:
        return 600


def cors_fallback_enabled() -> bool:
    return _bool_env("CORS_ENABLED", False)


class _CORSFallback(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        origin = request.headers.get("origin")
        if origin and request.method == "OPTIONS":
            return self._preflight_response(request, origin)

        resp = await call_next(request)

        # Add nosniff always (idempotent)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")

        # Add ACAO for simple/actual requests if header not already set
        if origin:
            lower_keys = {k.lower() for k in resp.headers.keys()}
            if "access-control-allow-origin" not in lower_keys:
                # Echo the request origin (tests expect explicit echo)
                resp.headers["Access-Control-Allow-Origin"] = origin
        return resp

    def _preflight_response(self, request: Request, origin: str) -> Response:
        methods = ",".join(_methods_env())
        req_hdrs = request.headers.get("access-control-request-headers", "*")
        resp = Response(status_code=204)
        # Always echo origin on preflight (tests require explicit origin, not wildcard)
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = methods
        resp.headers["Access-Control-Allow-Headers"] = req_hdrs or "*"
        resp.headers["Access-Control-Max-Age"] = str(_max_age())
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        return resp


def install_cors_fallback(app) -> None:
    if not cors_fallback_enabled():
        return
    app.add_middleware(_CORSFallback)
