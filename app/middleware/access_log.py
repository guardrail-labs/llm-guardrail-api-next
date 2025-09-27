from __future__ import annotations

import json
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("access")


def _request_id_from_request(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if rid is None:
        rid = request.scope.get("request_id")
    if rid is None:
        rid = request.headers.get("X-Request-ID")
    return str(rid) if rid else ""


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Simple JSON access log middleware."""

    async def dispatch(self, request: Request, call_next):
        rid = _request_id_from_request(request)
        response = await call_next(request)
        record = {
            "event": "request",
            "request_id": rid,
            "method": request.method,
            "path": str(request.url.path),
            "status_code": response.status_code,
        }
        try:
            logger.info(json.dumps(record, ensure_ascii=False))
        except Exception:
            pass
        return response
