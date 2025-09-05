from __future__ import annotations

import os
import uuid
from typing import Iterable, Tuple, cast

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Paths that bypass auth entirely (exact match)
_SAFE_PATHS: set[str] = {"/health", "/metrics"}

# Prefixes that bypass auth (OpenAI-compatible routes are public under /v1/)
_SAFE_PREFIXES: tuple[str, ...] = ("/v1/",)


def _is_auth_disabled() -> bool:
    return (os.environ.get("GUARDRAIL_DISABLE_AUTH") or "0") == "1"


def _is_safe_path(path: str) -> bool:
    if path in _SAFE_PATHS:
        return True
    return any(path.startswith(pfx) for pfx in _SAFE_PREFIXES)


def _has_auth_header(scope: Scope) -> bool:
    headers: Iterable[Tuple[bytes, bytes]] = cast(
        Iterable[Tuple[bytes, bytes]], scope.get("headers") or []
    )
    # lookup without building a full dict (keep it light)
    for k_bytes, v_bytes in headers:
        k = k_bytes.decode().lower()
        if k in ("x-api-key", "authorization"):
            return bool(v_bytes)
    return False


class AuthMiddleware:
    """
    Uniform API key/Authorization gate for the whole app.
    Exemptions:
      - OPTIONS preflight
      - /health and /metrics
      - Anything under /v1/
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        if (
            method == "OPTIONS"
            or _is_safe_path(path)
            or _is_auth_disabled()
            or _has_auth_header(scope)
        ):
            await self.app(scope, receive, send)
            return

        rid = _header(scope, "X-Request-ID") or str(uuid.uuid4())
        resp = JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized", "request_id": rid},
        )
        resp.headers["WWW-Authenticate"] = "Bearer"
        resp.headers["X-Request-ID"] = rid
        await resp(scope, receive, send)


def _header(scope: Scope, name: str) -> str:
    headers: Iterable[Tuple[bytes, bytes]] = cast(
        Iterable[Tuple[bytes, bytes]], scope.get("headers") or []
    )
    target = name.lower().encode("latin-1")
    for k_bytes, v_bytes in headers:
        if k_bytes.lower() == target:
            return v_bytes.decode("latin-1")
    return ""
