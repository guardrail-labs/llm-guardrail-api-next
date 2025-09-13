"""
CORS fallback middleware.

Adds ACAO for simple requests and handles preflight when Starlette's CORS
isn't active for dynamically toggled tests.

Env (read per request):
- CORS_ENABLED
- CORS_ALLOW_ORIGINS
- CORS_ALLOW_METHODS
- CORS_ALLOW_HEADERS
- CORS_MAX_AGE
"""

from __future__ import annotations

import os
from typing import Callable, Iterable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(val: Optional[str]) -> list[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]


def _is_allowed(origin: str, allowed: Iterable[str]) -> bool:
    for a in allowed:
        if a == "*" or a == origin:
            return True
    return False


class _CORSMiddlewareFallback(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[..., Response]) -> Response:
        if not _truthy(os.getenv("CORS_ENABLED", "0")):
            return await call_next(request)

        origin = request.headers.get("origin")
        allow_origins = _split_csv(os.getenv("CORS_ALLOW_ORIGINS", ""))

        # Preflight
        if (
            request.method.upper() == "OPTIONS"
            and request.headers.get("access-control-request-method")
            and origin
            and _is_allowed(origin, allow_origins)
        ):
            methods = os.getenv("CORS_ALLOW_METHODS", "GET,POST,OPTIONS")
            hdrs = os.getenv("CORS_ALLOW_HEADERS", "*")
            max_age = os.getenv("CORS_MAX_AGE", "600")

            resp = Response(status_code=204)
            resp.headers["access-control-allow-origin"] = origin
            resp.headers["access-control-allow-methods"] = methods
            resp.headers["access-control-allow-headers"] = hdrs
            resp.headers["access-control-max-age"] = max_age
            return resp

        # Simple/actual requests
        resp = await call_next(request)
        if origin and _is_allowed(origin, allow_origins):
            # Do not overwrite if upstream CORS already set it
            if "access-control-allow-origin" not in {k.lower(): v for k, v in resp.headers.items()}:
                resp.headers["access-control-allow-origin"] = origin
        return resp


def install_cors_fallback(app) -> None:
    app.add_middleware(_CORSMiddlewareFallback)
