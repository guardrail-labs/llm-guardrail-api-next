from __future__ import annotations

import gzip
import io
import os
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.middleware.env import get_bool


def _parse_min_size() -> int:
    raw = (os.getenv("COMPRESSION_MIN_SIZE_BYTES") or "").strip()
    try:
        v = int(raw)
        return v if v > 0 else 0
    except Exception:
        return 0


class GZipMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._enabled = get_bool("COMPRESSION_ENABLED")
        self._min_size = _parse_min_size()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self._enabled:
            return await call_next(request)

        ae = (request.headers.get("accept-encoding") or "").lower()
        wants_gzip = "gzip" in ae
        resp = await call_next(request)

        if not wants_gzip:
            return resp
        if resp.headers.get("content-encoding"):
            return resp

        # Extract body (iterator-safe)
        body = b""
        try:
            body = getattr(resp, "body", None) or b""
        except Exception:
            body = b""
        if not body:
            if getattr(resp, "body_iterator", None) is not None:
                chunks = [chunk async for chunk in resp.body_iterator]  # type: ignore[attr-defined]
                body = b"".join(chunks)

        if len(body) < self._min_size:
            # rebuild response since we might have consumed the iterator
            return Response(
                content=body,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                media_type=resp.media_type,
            )

        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(body)
        gz_body = buf.getvalue()

        headers = dict(resp.headers)
        headers.pop("content-length", None)
        headers["content-encoding"] = "gzip"
        headers["vary"] = headers.get("vary", "Accept-Encoding")
        return Response(
            content=gz_body,
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.media_type,
        )


def install_compression(app) -> None:
    if get_bool("COMPRESSION_ENABLED"):
        app.add_middleware(GZipMiddleware)

