from __future__ import annotations

from typing import Iterable, Tuple

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.observability.metrics import ingress_header_limit_blocked

try:  # pragma: no cover - fallback for optional import during tests
    from app.observability.metrics import _limit_tenant_bot_labels
except Exception:  # pragma: no cover

    def _limit_tenant_bot_labels(tenant: str, bot: str) -> tuple[str, str]:
        return (tenant[:32], bot[:32])


from app.services.config_store import get_config


def _to_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
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

        raw_headers: Iterable[Tuple[bytes, bytes]] = scope.get("headers") or ()
        headers = tuple(raw_headers)

        if max_count and len(headers) > max_count:
            _record_header_limit_block(scope, "count")
            await self._reject(
                scope,
                receive,
                send,
                reason="count",
                detail="Request header limit exceeded: too many headers",
            )
            return

        if max_value:
            for _, value in headers:
                if value is None:
                    continue
                if len(value) > max_value:
                    _record_header_limit_block(scope, "value_len")
                    await self._reject(
                        scope,
                        receive,
                        send,
                        reason="value_len",
                        detail="Request header limit exceeded: header value too large",
                    )
                    return

        await self.app(scope, receive, send)

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        reason: str,
        detail: str,
    ) -> None:
        response = PlainTextResponse(detail, status_code=431)
        response.headers["Connection"] = "close"
        response.headers["X-Guardrail-Header-Limit-Blocked"] = reason
        await response(scope, receive, send)


def _tenant_bot(scope: Scope) -> tuple[str, str]:
    try:
        from starlette.requests import Request

        request = Request(scope)
        tenant = request.headers.get("X-Guardrail-Tenant", "") or ""
        bot = request.headers.get("X-Guardrail-Bot", "") or ""
        return _limit_tenant_bot_labels(tenant, bot)
    except Exception:  # pragma: no cover
        return ("", "")


def _record_header_limit_block(scope: Scope, reason: str) -> None:
    try:
        tenant, bot = _tenant_bot(scope)
        ingress_header_limit_blocked.labels(
            tenant=tenant,
            bot=bot,
            reason=reason,
        ).inc()
    except Exception:  # pragma: no cover
        return
