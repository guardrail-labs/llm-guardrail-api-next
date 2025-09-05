from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Iterable, Optional, Tuple, cast

from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Context variable for request id
_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_HEADER = "X-Request-ID"


def get_request_id() -> Optional[str]:
    """Return the current request id (if any) set by RequestID middleware."""
    return _REQUEST_ID.get()


class RequestIDMiddleware:
    """
    Ensures every request has a stable request id:
    - Accept an incoming X-Request-ID if present.
    - Otherwise generate a new UUID4.
    - Expose it via contextvar for other modules (logging/tracing).
    - Echo it back on the response headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        rid = _header(scope, _HEADER) or str(uuid.uuid4())
        token = _REQUEST_ID.set(rid)

        async def send_wrapped(message: Message) -> None:
            if message.get("type") == "http.response.start":
                _append_header(message, _HEADER, rid)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            _REQUEST_ID.reset(token)


def _header(scope: Scope, name: str) -> str:
    headers: Iterable[Tuple[bytes, bytes]] = cast(
        Iterable[Tuple[bytes, bytes]], scope.get("headers") or []
    )
    target = name.lower().encode("latin-1")
    for k_bytes, v_bytes in headers:
        if k_bytes.lower() == target:
            return v_bytes.decode("latin-1")
    return ""


def _append_header(message: Message, name: str, value: str) -> None:
    headers = message.setdefault("headers", [])
    headers.append((name.encode("latin-1"), value.encode("latin-1")))
