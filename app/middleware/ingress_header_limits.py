from __future__ import annotations

from collections.abc import Iterable

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.services.config_store import get_config


def _to_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return int(value)
    try:
        return int(str(value).strip())
    except Exception:
        return 0


class IngressHeaderLimitsMiddleware:
    """Enforce configurable inbound header count and value size limits."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        cfg = get_config()
        if not bool(cfg.get("ingress_header_limits_enabled", False)):
            await self.app(scope, receive, send)
            return

        max_count = _to_int(cfg.get("ingress_max_header_count", 0))
        max_value = _to_int(cfg.get("ingress_max_header_value_bytes", 0))

        raw_headers: Iterable[tuple[bytes, bytes]] = scope.get("headers") or ()
        headers = tuple(raw_headers)

        if max_count and len(headers) > max_count:
            await self._reject(scope, receive, send, "too many headers")
            return

        if max_value:
            for _, value in headers:
                if len(value) > max_value:
                    await self._reject(scope, receive, send, "header value too large")
                    return

        await self.app(scope, receive, send)

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        reason: str,
    ) -> None:
        response = PlainTextResponse(f"Request header limit exceeded: {reason}", status_code=431)
        response.headers["Connection"] = "close"
        await response(scope, receive, send)
