from __future__ import annotations

import json
import logging
import os
import time
from typing import Awaitable, Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.middleware.env import get_bool
from app.middleware.request_id import get_request_id

_LOG = logging.getLogger("guardrail")


def _first_truthy(val: Optional[str], default: str = "") -> str:
    return (val or "").strip() or default


class JSONAccessLogMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._enabled = get_bool("LOG_JSON_ENABLED")
        self._log_reqs = get_bool("LOG_REQUESTS_ENABLED")
        paths_raw = os.getenv("LOG_REQUESTS_PATHS", "").strip()
        self._paths = {p.strip() for p in paths_raw.split(",") if p.strip()}
        self._snap_emitted = False

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self._enabled:
            return await call_next(request)

        # Emit a one-shot config snapshot the first time we see a request
        if not self._snap_emitted:
            try:
                _LOG.info(
                    json.dumps(
                        {
                            "event": "config_snapshot",
                            "cors_allow_origins": _first_truthy(
                                os.getenv("CORS_ALLOW_ORIGINS")
                            ),
                            "max_request_bytes": _first_truthy(
                                os.getenv("MAX_REQUEST_BYTES")
                            ),
                            "compression_enabled": get_bool("COMPRESSION_ENABLED"),
                            "compression_min_size_bytes": _first_truthy(
                                os.getenv("COMPRESSION_MIN_SIZE_BYTES")
                            ),
                            "csp_enabled": get_bool("CSP_ENABLED"),
                        }
                    )
                )
            finally:
                self._snap_emitted = True

        start = time.perf_counter()
        resp = await call_next(request)

        # Access log only for selected paths if enabled
        if self._log_reqs and (not self._paths or request.url.path in self._paths):
            rid = (
                resp.headers.get("X-Request-ID")
                or get_request_id()
                or ""  # last resort
            )
            try:
                duration_ms = int((time.perf_counter() - start) * 1000)
            except Exception:
                duration_ms = 0

            _LOG.info(
                json.dumps(
                    {
                        "event": "http_access",
                        "path": request.url.path,
                        "method": request.method,
                        "status": resp.status_code,
                        "duration_ms": duration_ms,
                        "request_id": rid,
                    }
                )
            )

        return resp


def install_request_logging(app) -> None:
    app.add_middleware(JSONAccessLogMiddleware)

