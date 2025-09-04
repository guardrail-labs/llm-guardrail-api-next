from __future__ import annotations

import os
import uuid
from typing import Optional

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.services.quota.store import FixedWindowQuotaStore


def _enabled(env: str, default: bool = True) -> bool:
    raw = os.getenv(env)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _parse_bearer(auth_header: str) -> str:
    parts = (auth_header or "").split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _api_key_from_headers(headers: dict[str, str]) -> str:
    return headers.get("x-api-key") or _parse_bearer(headers.get("authorization") or "")


def _trace() -> str:
    return uuid.uuid4().hex


class QuotaMiddleware:
    """
    Per-API-key quotas using fixed UTC day and month windows.
    Emits X-Quota-* headers and 429 JSON with 'quota_exhausted' when exceeded.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: Optional[bool] = None,
        per_day: Optional[int] = None,
        per_month: Optional[int] = None,
    ) -> None:
        self.app = app
        self.enabled = _enabled("QUOTA_ENABLED", True) if enabled is None else enabled
        day = int(os.getenv("QUOTA_PER_DAY", str(per_day or 100000)))
        mon = int(os.getenv("QUOTA_PER_MONTH", str(per_month or 2000000)))
        self.store = FixedWindowQuotaStore(per_day=day, per_month=mon)
        self.per_day = day
        self.per_month = mon

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        headers = dict((k.decode().lower(), v.decode()) for k, v in scope.get("headers", []))
        key = _api_key_from_headers(headers) or "anon"
        decision = self.store.check_and_inc(key)

        def attach_headers(message: Message) -> None:
            hdrs = message.setdefault("headers", [])
            day_rem = max(0, int(decision["day_remaining"]))
            mon_rem = max(0, int(decision["month_remaining"]))
            retry = max(1, int(decision["retry_after_s"]))

            hdrs.append((b"X-Quota-Limit-Day", str(self.per_day).encode()))
            hdrs.append((b"X-Quota-Limit-Month", str(self.per_month).encode()))
            hdrs.append((b"X-Quota-Remaining-Day", str(day_rem).encode()))
            hdrs.append((b"X-Quota-Remaining-Month", str(mon_rem).encode()))
            hdrs.append((b"X-Quota-Reset", str(retry).encode()))

        if not decision["allowed"]:
            body = {
                "code": "quota_exhausted",
                "detail": f"{decision['reason']} quota exceeded",
                "retry_after_seconds": decision["retry_after_s"],
                "trace_id": _trace(),
            }
            resp = JSONResponse(body, status_code=429)
            resp.headers["Retry-After"] = str(decision["retry_after_s"])
            await _send_with_extra_headers(resp, scope, receive, send, attach_headers)
            return

        async def send_wrapped(message: Message) -> None:
            if message.get("type") == "http.response.start":
                attach_headers(message)
            await send(message)

        await self.app(scope, receive, send_wrapped)


async def _send_with_extra_headers(response, scope: Scope, receive: Receive, send: Send, attach):
    async def send_wrapped(message: Message) -> None:
        if message.get("type") == "http.response.start":
            attach(message)
        await send(message)

    await response(scope, receive, send_wrapped)
