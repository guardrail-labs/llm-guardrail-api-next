from __future__ import annotations

import os
import uuid
from typing import Awaitable, Callable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.audit_forwarder import emit_audit_event
from app.services.policy import current_rules_version
from app.services.quota.store import FixedWindowQuotaStore
from app.shared.headers import BOT_HEADER, TENANT_HEADER
from app.shared.request_meta import get_client_meta
from app.telemetry.metrics import inc_quota_reject_tenant_bot

# Optional: lightweight fingerprint for parity with routes that log quotas
try:
    from app.services.verifier import content_fingerprint
except Exception:  # pragma: no cover
    def content_fingerprint(_: str) -> str:  # type: ignore
        return "quota"


def _truthy(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _tenant_bot_from_headers(request: Request) -> tuple[str, str]:
    tenant = request.headers.get(TENANT_HEADER) or "default"
    bot = request.headers.get(BOT_HEADER) or "default"
    return tenant, bot


def _trace_id() -> str:
    return uuid.uuid4().hex


class QuotaMiddleware(BaseHTTPMiddleware):
    """
    Global per-tenant:bot quotas using fixed UTC day and month windows.

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
        "trace_id": "<uuid>"
      }
      + Retry-After header.
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
        self.enabled = _truthy(os.getenv("QUOTA_ENABLED"), True) if enabled is None else enabled
        day = int(os.getenv("QUOTA_PER_DAY") or (str(per_day) if per_day is not None else "100000"))
        mon = int(
            os.getenv("QUOTA_PER_MONTH")
            or (str(per_month) if per_month is not None else "2000000")
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

        tenant_id, bot_id = _tenant_bot_from_headers(request)
        key = f"{tenant_id}:{bot_id}"
        decision = self.store.check_and_inc(key)

        if not decision["allowed"]:
            # Metrics + audit
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
                        "request_id": request.headers.get("X-Request-ID") or _trace_id(),
                        "direction": "ingress",
                        "decision": "deny",
                        "rule_hits": None,
                        "policy_version": current_rules_version(),
                        "status_code": 429,
                        "redaction_count": 0,
                        "hash_fingerprint": content_fingerprint("quota"),
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
                "trace_id": _trace_id(),
            }
            error_resp = JSONResponse(body, status_code=429)
            self._attach_headers(error_resp, decision)
            error_resp.headers["Retry-After"] = str(int(decision["retry_after_s"]))
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

