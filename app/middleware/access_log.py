from __future__ import annotations

import json
import logging
import uuid
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.telemetry.tracing import get_request_id

logger = logging.getLogger("access")


class AccessLogMiddleware:
    """Simple JSON access log middleware (ASGI-safe)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        rid = get_request_id() or _header(scope, "X-Request-ID") or str(uuid.uuid4())
        method = scope.get("method", "")
        path = scope.get("path", "")
        status_code = 0

        async def send_wrapped(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 0))
            await send(message)

        await self.app(scope, receive, send_wrapped)

        record = {
            "event": "request",
            "request_id": rid,
            "method": method,
            "path": str(path),
            "status_code": status_code,
        }
        try:
            logger.info(json.dumps(record, ensure_ascii=False))
        except Exception:
            pass


def _header(scope: Scope, name: str) -> str:
    target = name.lower().encode("latin-1")
    for k, v in scope.get("headers") or []:
        if k.lower() == target:
            return v.decode("latin-1")
    return ""
