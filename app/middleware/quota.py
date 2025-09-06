from __future__ import annotations

import os
import uuid
from typing import Awaitable, Callable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.quota.store import FixedWindowQuotaStore
from app.shared.headers import TENANT_HEADER, BOT_HEADER
from app.shared.request_meta import get_client_meta

# Expose these names so tests can monkeypatch them on this module.
from app.services.audit_forwarder import emit_audit_event as _emit_audit_event
from app.telemetry.metrics import (
    inc_quota_reject_tenant_bot as _inc_quota_reject_tenant_bot,
)

emit_audit_event = _emit_audit_event
inc_quota_reject_tenant_bot = _inc_quota_reject_tenant_bot


def _truthy(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


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


def _req_id(request: Request) -> str:
    # Prefer inbound request id if present; else generate one
    return request.headers.get("X-Request-ID") or uuid.uuid4().hex


class QuotaMiddleware(BaseHTTPMiddleware):
    """
    Global per-API-key quotas using fixed UTC day and month windows.

    Always sets:
      - X-Quota-Limit-Day
      - X-Quota-Limit-Month
      - X-Quota-Remaining-Day
      - X-Quota-Remaining-Month
      - X-Quota-Reset  (seconds until earlier of day/month reset)

    On exhaustion returns 429 with:
      {
        "code": "quota_exhausted",
        "detail": "<day|month> quota exceeded",
        "retry_after_seconds": <int>,
        "trace_id": "<uuid>",
        "request_id": "<uuid or inbound>"
      }
      + Retry-After + X-Request-ID headers.
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
        # Default OFF unless explicitly enabled
        self.enabled = _truthy(os.getenv("QUOTA_ENABLED"), False) if enabled is None else enabled
        day = int(os.getenv("QUOTA_PER_DAY") or (str(per_day) if per_day is not None else "100000"))
        mon = int(
            os.getenv("QUOTA_PER_MONTH") or (str(per_month) if per_month is not None else "2000000")
        )
        self.per_day = day
        self.per_month = mon
        self.store = FixedWindowQuotaStore(per_day=day, per_month=mon)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        key = _api_key_from_headers(request) or "anon"
        decision = self.store.check_and_inc(key)

        if not decision["allowed"]:
            tenant_id = request.headers.get(TENANT_HEADER) or "default"
            bot_id = request.headers.get(BOT_HEADER) or "default"
            rid = _req_id(request)

            # Telemetry: metrics + audit (tests may monkeypatch these names)
            try:
                inc_quota_reject_tenant_bot(tenant_id, bot_id)
            except Exception:
                pass
            try:
                emit_audit_event(
                    {
                        "ts": None,
                        "tenant_id": tenant_id,
                        "bot_id": bot_id,
                        "request_id": rid,
                        "direction": "ingress",
                        "decision": "deny",
                        "rule_hits": None,
                        "status_code": 429,
                        "redaction_count": 0,
                        "hash_fingerprint": None,
                        "payload_bytes": 0,
                        "sanitized_bytes": 0,
                        "meta": {
                            "endpoint": request.url.path,
                            "client": get_client_meta(request),
                        },
                    }
                )
            except Exception:
                pass

            body = {
                "code": "quota_exhausted",
                "detail": f"{decision['reason']} quota exceeded",
                "retry_after_seconds": int(decision["retry_after_s"]),
                "trace_id": uuid.uuid4().hex,
                "request_id": rid,
            }
            error_resp = JSONResponse(body, status_code=429)
            self._attach_headers(error_resp, decision)
            error_resp.headers["Retry-After"] = str(int(decision["retry_after_s"]))
            error_resp.headers["X-Request-ID"] = rid
            return error_resp

        resp = await call_next(request)
        self._attach_headers(resp, decision)
        return resp

    def _attach_headers(self, resp: Response, decision) -> None:
        resp.headers["X-Quota-Limit-Day"] = str(self.per_day)
        resp.headers["X-Quota-Limit-Month"] = str(self.per_month)
        resp.headers["X-Quota-Remaining-Day"] = str(max(0, int(decision["day_remaining"])))
        resp.headers["X-Quota-Remaining-Month"] = str(max(0, int(decision["month_remaining"])))
        resp.headers["X-Quota-Reset"] = str(max(1, int(decision["retry_after_s"])))
