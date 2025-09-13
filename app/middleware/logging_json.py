"""
JSON access logging middleware + one-time config snapshot.

Env (read per request):
- LOG_JSON_ENABLED: enable JSON logs
- LOG_REQUESTS_ENABLED: emit per-request access log
- LOG_REQUESTS_PATHS: CSV allowlist of paths to log (optional)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Awaitable, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.middleware.request_id import get_request_id

_LOGGER = logging.getLogger("guardrail")
_SNAPSHOT_EMITTED = False


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _paths() -> Optional[set[str]]:
    raw = os.getenv("LOG_REQUESTS_PATHS", "")
    if not raw:
        return None
    return {p.strip() for p in raw.split(",") if p.strip()}


def _emit_snapshot_once(response: Response) -> None:
    global _SNAPSHOT_EMITTED
    if _SNAPSHOT_EMITTED:
        return
    _SNAPSHOT_EMITTED = True

    data = {
        "event": "config_snapshot",
        "cors_allow_origins": os.getenv("CORS_ALLOW_ORIGINS", ""),
        "max_request_bytes": os.getenv("MAX_REQUEST_BYTES", ""),
        "compression_enabled": _truthy(os.getenv("COMPRESSION_ENABLED", "0")),
        "compression_min_size_bytes": os.getenv("COMPRESSION_MIN_SIZE_BYTES", ""),
        "csp_enabled": _truthy(os.getenv("CSP_ENABLED", "0")),
    }
    _LOGGER.info(json.dumps(data))


class _JSONLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        enabled = _truthy(os.getenv("LOG_JSON_ENABLED", "0"))
        if not enabled:
            return await call_next(request)

        t0 = time.perf_counter()
        resp: Response = await call_next(request)

        # Emit snapshot once (after we have headers, including X-Request-ID)
        _emit_snapshot_once(resp)

        if _truthy(os.getenv("LOG_REQUESTS_ENABLED", "0")):
            allow = _paths()
            if allow is None or request.url.path in allow:
                rid = resp.headers.get("X-Request-ID") or (get_request_id() or "")
                evt = {
                    "event": "http_access",  # <- required by tests
                    "path": request.url.path,
                    "method": request.method,
                    "status": resp.status_code,
                    "duration_ms": int((time.perf_counter() - t0) * 1000),
                    "request_id": rid,
                }
                _LOGGER.info(json.dumps(evt))

        return resp


def install_logging_json(app) -> None:
    app.add_middleware(_JSONLoggingMiddleware)
