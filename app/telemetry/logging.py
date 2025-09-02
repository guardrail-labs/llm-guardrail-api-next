"""Logging helpers for the Guardrail API."""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict

from app.config import get_settings
from app.telemetry.tracing import get_request_id

logger = logging.getLogger("guardrail")


def configure_logging() -> None:
    """Configure base logging format and level."""
    s = get_settings()
    level = getattr(logging, (s.LOG_LEVEL or "INFO").upper(), logging.INFO)
    logging.basicConfig(level=level, stream=sys.stdout)


class RequestLoggingMiddleware:
    """Legacy helper retained for compatibility."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):  # pragma: no cover - legacy
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request_id = get_request_id() or scope.get("headers", {}).get(b"x-request-id")
        async def _send(message: Dict[str, Any]):
            if message.get("type") == "http.response.start":
                record: Dict[str, Any] = {
                    "event": "guardrail_request",
                    "request_id": request_id,
                    "status_code": message.get("status", 0),
                }
                try:
                    logger.info(json.dumps(record, ensure_ascii=False))
                except Exception:
                    pass
            await send(message)
        await self.app(scope, receive, _send)
