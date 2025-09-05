from __future__ import annotations

import json
import logging
import uuid
from typing import Iterable, Tuple, cast

from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.telemetry.tracing import get_request_id

logger = logging.getLogger("access")


class AccessLogMiddleware:
    """Simple JSON access log middleware."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        rid = get_request_id() or _header(scope, "X-Request-ID") or str(uuid.uuid4())

        status_code_holder = {"code": 0}

        async def send_wrapped(message: Message) -> None:
            if message.get("type") == "http.response.start":
                status_code_holder["code"] = int(message.get("status", 0) or 0)
            await send(message)

        await self.app(scope, receive, send_wrapped)

        record = {
            "event": "request",
            "request_id": rid,
            "method": scope.get("method", ""),
            "path": str(scope.get("path", "")),
            "status_code": status_code_holder["code"],
        }
        try:
            logger.info(json.dumps(record, ensure_ascii=False))
        except Exception:
            pass


def _header(scope: Scope, name: str) -> str:
    headers: Iterable[Tuple[bytes, bytes]] = cast(
        Iterable[Tuple[bytes, bytes]], scope.get("headers") or []
    )
    target = name.lower().encode("latin-1")
    for k_bytes, v_bytes in headers:
        if k_bytes.lower() == target:
            return v_bytes.decode("latin-1")
    return ""
