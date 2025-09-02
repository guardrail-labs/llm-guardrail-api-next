from __future__ import annotations

import json
import logging
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.telemetry.tracing import get_request_id

logger = logging.getLogger("access")


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Simple JSON access log middleware."""

    async def dispatch(self, request: Request, call_next):
        rid = get_request_id() or request.headers.get("X-Request-ID") or str(uuid.uuid4())
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
