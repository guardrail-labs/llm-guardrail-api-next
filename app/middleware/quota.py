from __future__ import annotations

import os
import uuid
from typing import Awaitable, Callable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.quota.store import FixedWindowQuotaStore


def _enabled(env: str, default: bool = True) -> bool:
    raw = os.getenv(env)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _api_key_from_headers(request: Request) -> str:
    return (
        request.headers.get("x-api-key")
        or request.headers.get("X-API-Key")
        or _parse_bearer(request.headers.get("authorization") or "")
        or ""
    )


def _parse_bearer(auth_header: str) -> str:
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _trace() -> str:
    return uuid.uuid4().hex


class QuotaMiddleware(BaseHTTPMiddleware):
    """
    Per-API-key quotas using fixed UTC day and month windows.
    - Headers on all responses:
      X-Quota-Limit-Day / X-Quota-Remaining-Day
      X-Quota-Limit-Month / X-Quota-Remaining-Month
      X-Quota-Reset: seconds until the *sooner* reset (day or month)
    - On exhaustion: 429 with code 'quota_exhausted' and Retry-After.
    """

    def __init__(
        self,
        app: Callable,
        *,
        enabled: Optional[bool] = None,
        per_day: Optional[int] = None,
        per_month: Optional[int] = None,
    ) -> None:
        super().__init__(app)
        self.enabled = _enabled("QUOTA_ENABLED", True) if enabled is None else enabled
        day = int(os.getenv("QUOTA_PER_DAY", str(per_day or 100000)))
        mon = int(os.getenv("QUOTA_PER_MONTH", str(per_month or 2000000)))
        self.store = FixedWindowQuotaStore(per_day=day, per_month=mon)
        self.per_day = day
        self.per_month = mon

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        key = _api_key_from_headers(request) or "anon"
        decision = self.store.check_and_inc(key)

        if not decision["allowed"]:
            body = {
                "code": "quota_exhausted",
                "detail": f"{decision['reason']} quota exceeded",
                "retry_after_seconds": decision["retry_after_s"],
                "trace_id": _trace(),
            }
            limited_resp = JSONResponse(body, status_code=429)
            self._attach_headers(limited_resp, decision)
            limited_resp.headers["Retry-After"] = str(decision["retry_after_s"])
            return limited_resp

        response = await call_next(request)
        self._attach_headers(response, decision)
        return response

    def _attach_headers(self, resp: Response, decision) -> None:
        resp.headers["X-Quota-Limit-Day"] = str(self.per_day)
        resp.headers["X-Quota-Limit-Month"] = str(self.per_month)
        resp.headers["X-Quota-Remaining-Day"] = str(max(0, int(decision["day_remaining"])))
        resp.headers["X-Quota-Remaining-Month"] = str(max(0, int(decision["month_remaining"])))
        resp.headers["X-Quota-Reset"] = str(max(1, int(decision["retry_after_s"])))
