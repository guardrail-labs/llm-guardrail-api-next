from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Optional

from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Context variable for request id
_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

_HEADER = "X-Request-ID"


def get_request_id() -> Optional[str]:
    """Return the current request id (if any)."""
    return _REQUEST_ID.get()


class RequestIDMiddleware:
    """
    ASGI middleware that ensures every request has a request id and that it's echoed
    back on the response, while also exposing it via ContextVar.
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
                headers = message.setdefault("headers", [])
                headers.append((_HEADER.encode("latin-1"), rid.encode("latin-1")))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            _REQUEST_ID.reset(token)


def _header(scope: Scope, name: str) -> str:
    target = name.lower().encode("latin-1")
    for k, v in scope.get("headers") or []:
        if k.lower() == target:
            return v.decode("latin-1")
    return ""
