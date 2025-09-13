"""
Simple gzip compression middleware controlled by env.

Env (read per request):
- COMPRESSION_ENABLED: toggle (default off)
- COMPRESSION_MIN_SIZE_BYTES: minimum size to compress (default 500)
"""

from __future__ import annotations

import gzip
import io
import os
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _min_size() -> int:
    try:
        return max(int(os.getenv("COMPRESSION_MIN_SIZE_BYTES", "500")), 0)
    except Exception:
        return 500


class _CompressionMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp: Response = await call_next(request)

        if not _truthy(os.getenv("COMPRESSION_ENABLED", "0")):
            return resp

        if "gzip" not in (request.headers.get("accept-encoding") or ""):
            return resp

        if resp.headers.get("content-encoding"):
            return resp  # already encoded

        # Materialize body
        body: bytes = b""
        if hasattr(resp, "body_iterator") and resp.body_iterator is not None:
            chunks = []
            async for chunk in resp.body_iterator:
                chunks.append(chunk)
            body = b"".join(chunks)
        else:
            body = getattr(resp, "body", b"")

        if len(body) < _min_size():
            if hasattr(resp, "body_iterator"):
                new_resp = Response(
                    content=body,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    media_type=resp.media_type,
                )
                return new_resp
            return resp

        # Compress
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(body)
        gz_bytes = buf.getvalue()

        new_headers = dict(resp.headers)
        new_headers["Content-Encoding"] = "gzip"
        vary = new_headers.get("Vary")
        new_headers["Vary"] = "Accept-Encoding" if not vary else f"{vary}, Accept-Encoding"
        new_headers["Content-Length"] = str(len(gz_bytes))

        return Response(
            content=gz_bytes,
            status_code=resp.status_code,
            headers=new_headers,
            media_type=resp.media_type,
        )


def install_compression(app) -> None:
    app.add_middleware(_CompressionMiddleware)
