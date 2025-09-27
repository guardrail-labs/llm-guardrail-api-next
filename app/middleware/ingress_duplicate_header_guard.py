from __future__ import annotations

from typing import Dict, Iterable, Tuple

from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.observability.metrics import (
    duplicate_header_blocked,
    duplicate_header_seen,
)
from app.services.config_store import (
    DUPLICATE_HEADER_UNIQUE_DEFAULT,
    get_config,
)

try:  # pragma: no cover - optional label limiter
    from app.observability.metrics import _limit_tenant_bot_labels
except Exception:  # pragma: no cover - fallback stub

    def _limit_tenant_bot_labels(tenant: str, bot: str) -> tuple[str, str]:
        return tenant[:32], bot[:32]


def _tenant_bot_labels(request: Request) -> tuple[str, str]:
    tenant = request.headers.get("X-Guardrail-Tenant", "") or ""
    bot = request.headers.get("X-Guardrail-Bot", "") or ""
    return _limit_tenant_bot_labels(tenant, bot)


class IngressDuplicateHeaderGuardMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        config = dict(get_config())
        raw_mode = config.get("ingress_duplicate_header_guard_mode", "off")
        mode = str(raw_mode or "off").lower()
        if mode == "off":
            await self.app(scope, receive, send)
            return

        raw_headers: Iterable[Tuple[bytes, bytes]] = tuple(scope.get("headers") or ())
        counts: Dict[str, int] = {}
        for raw_name, _ in raw_headers:
            name = (raw_name or b"").decode("latin-1", "ignore").strip().lower()
            if not name:
                continue
            counts[name] = counts.get(name, 0) + 1

        duplicates = sorted(name for name, count in counts.items() if count > 1)
        if not duplicates:
            await self.app(scope, receive, send)
            return

        unique_cfg = config.get("ingress_duplicate_header_unique")
        if isinstance(unique_cfg, Iterable) and not isinstance(unique_cfg, (str, bytes)):
            source = unique_cfg
        else:
            source = DUPLICATE_HEADER_UNIQUE_DEFAULT
        unique = {str(item).strip().lower() for item in source}

        request = Request(scope, receive=receive)
        tenant_label, bot_label = _tenant_bot_labels(request)

        for name in duplicates:
            duplicate_header_seen.labels(
                tenant=tenant_label,
                bot=bot_label,
                mode=mode,
                name=name,
            ).inc()

        blocked = sorted(name for name in duplicates if name in unique)
        if mode == "block" and blocked:
            for name in blocked:
                duplicate_header_blocked.labels(
                    tenant=tenant_label,
                    bot=bot_label,
                    name=name,
                ).inc()

            response = PlainTextResponse(
                "Bad Request: duplicate unique header",
                status_code=400,
            )
            response.headers["X-Guardrail-Duplicate-Header-Blocked"] = ",".join(blocked)
            response.headers["Connection"] = "close"
            await response(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if mode == "log" and message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append(
                    (
                        b"x-guardrail-duplicate-header-audit",
                        ",".join(duplicates).encode("utf-8"),
                    )
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)
