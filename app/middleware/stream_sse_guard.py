from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_SSE_HEADER = (b"x-sse", b"1")
_CT_HDR = b"content-type"
_CE_HDR = b"content-encoding"
_CC_HDR = b"cache-control"
_CONN_HDR = b"connection"
_XAB_HDR = b"x-accel-buffering"
_PRAGMA_HDR = b"pragma"


class SSEGuardMiddleware:
    """
    Header hygiene for Server-Sent Events (SSE).

    - Enforce text/event-stream content type
    - Disable proxies' buffering/compression
    - Set no-cache, keep-alive
    - No-ops for non-SSE responses
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if _is_sse(headers):
                    _set_or_replace(headers, _CT_HDR, b"text/event-stream; charset=utf-8")
                    _set_or_replace(headers, _CC_HDR, b"no-cache, no-transform")
                    _set_or_replace(headers, _CONN_HDR, b"keep-alive")
                    _set_or_replace(headers, _XAB_HDR, b"no")
                    _set_or_replace(headers, _PRAGMA_HDR, b"no-cache")
                    _drop_header(headers, _CE_HDR)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _is_sse(headers: list[tuple[bytes, bytes]]) -> bool:
    # Marked by x-sse: 1 or media type already set by route
    for k, v in headers:
        lk = k.lower()
        lv = v.lower()
        if lk == _CT_HDR and b"text/event-stream" in lv:
            return True
        if k.lower() == _SSE_HEADER[0] and v == _SSE_HEADER[1]:
            return True
    return False


def _set_or_replace(headers: list[tuple[bytes, bytes]], key: bytes, value: bytes) -> None:
    lk = key.lower()
    for i, (k, _) in enumerate(headers):
        if k.lower() == lk:
            headers[i] = (key, value)
            return
    headers.append((key, value))


def _drop_header(headers: list[tuple[bytes, bytes]], key: bytes) -> None:
    lk = key.lower()
    i = 0
    while i < len(headers):
        if headers[i][0].lower() == lk:
            headers.pop(i)
        else:
            i += 1
