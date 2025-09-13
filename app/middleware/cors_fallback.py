from __future__ import annotations

import os
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.middleware.env import get_bool


class _CORSFallback(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        origins_raw = (os.getenv("CORS_ALLOW_ORIGINS") or "").split(",")
        self._origins = {o.strip() for o in origins_raw if o.strip()}
        self._allow_methods = os.getenv("CORS_ALLOW_METHODS", "GET,POST,OPTIONS").strip()
        self._allow_headers = os.getenv("CORS_ALLOW_HEADERS", "").strip()
        try:
            self._max_age = int(os.getenv("CORS_MAX_AGE", "600").strip())
        except Exception:
            self._max_age = 600

    def _is_origin_allowed(self, origin: str) -> bool:
        if not get_bool("CORS_ENABLED"):
            return False
        if not self._origins or "*" in self._origins:
            return True
        return origin in self._origins

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        origin = request.headers.get("origin")
        method = request.method.upper()

        # Handle preflight
        if (
            method == "OPTIONS"
            and origin
            and request.headers.get("access-control-request-method")
        ):
            if self._is_origin_allowed(origin):
                h = {
                    "access-control-allow-origin": origin,
                    "access-control-allow-methods": self._allow_methods,
                    "access-control-allow-headers": self._allow_headers or "*",
                    "access-control-max-age": str(self._max_age),
                    "x-content-type-options": "nosniff",
                }
                return Response(status_code=204, headers=h)
            return Response(status_code=400)

        # Normal request
        resp: Response = await call_next(request)
        if origin and "access-control-allow-origin" not in {
            k.lower(): v for k, v in resp.headers.items()
        }:
            if self._is_origin_allowed(origin):
                resp.headers.setdefault("access-control-allow-origin", origin)
        return resp


def install_cors_fallback(app) -> None:
    if get_bool("CORS_ENABLED"):
        app.add_middleware(_CORSFallback)

