from __future__ import annotations

import gzip
import io
import os
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, StreamingResponse

from app.middleware.env import get_bool


def _parse_min_size() -> int:
    raw = (os.getenv("COMPRESSION_MIN_SIZE_BYTES") or "").strip()
    try:
        v = int(raw)
        return v if v > 0 else 0
    except Exception:
        return 0


def _wants_gzip(request: Request) -> bool:
    ae = (request.headers.get("accept-encoding") or "").lower()
    return "gzip" in ae


def _is_streaming_response(resp: Response) -> bool:
    # Only treat *true* streaming responses as streaming.
    # Many non-streaming responses also expose a body_iterator; don't use that.
    return isinstance(resp, StreamingResponse)


def _is_sse(resp: Response) -> bool:
    ctype = (resp.headers.get("content-type") or "").lower()
    return "text/event-stream" in ctype


def _add_vary_accept_encoding(headers: dict[str, str]) -> None:
    existing = headers.get("Vary")
    if not existing:
        headers["Vary"] = "Accept-Encoding"
        return
    # Append if not already present (case-insensitive)
    tokens = [t.strip().lower() for t in existing.split(",")]
    if "accept-encoding" not in tokens:
        headers["Vary"] = f"{existing}, Accept-Encoding"


class GZipMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._enabled = get_bool("COMPRESSION_ENABLED")
        self._min_size = _parse_min_size()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Fast-path: off or client doesn't accept gzip -> do nothing.
        if not self._enabled or not _wants_gzip(request):
            return await call_next(request)

        resp = await call_next(request)

        # Never compress these cases.
        if (
            resp.status_code in (204, 304)  # no-body statuses
            or resp.headers.get("content-encoding")  # already encoded (e.g., upstream)
            or _is_streaming_response(resp)          # true streaming bodies
            or _is_sse(resp)                          # explicit SSE content-type
        ):
            return resp

        # Try to read the in-memory body. If it's not there, skip (don't buffer).
        body: bytes = b""
        try:
            maybe = getattr(resp, "body", None)
            if isinstance(maybe, (bytes, bytearray)):
                body = bytes(maybe)
        except Exception:
            body = b""

        # If we couldn't get a concrete body (or it's too small), skip compression.
        if not body or len(body) < self._min_size:
            return resp

        # Compress the body.
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(body)
        gz_body = buf.getvalue()

        # Prepare headers for the compressed response.
        headers: dict[str, str] = dict(resp.headers)
        # Remove any length; Starlette will set it from the new body.
        for k in ("content-length", "Content-Length"):
            headers.pop(k, None)
        headers["Content-Encoding"] = "gzip"
        _add_vary_accept_encoding(headers)

        return Response(
            content=gz_body,
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.media_type,
            background=resp.background,
        )


def install_compression(app) -> None:
    if get_bool("COMPRESSION_ENABLED"):
        app.add_middleware(GZipMiddleware)
