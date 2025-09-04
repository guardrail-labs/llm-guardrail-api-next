"""
Abuse gate middleware: integrates the AbuseEngine with a pluggable verdict hook.

Behavior
- Builds a Subject from hashed API key + IP.
- Checks current mode (allow/execute_locked/full_quarantine).
- Fetches a verdict via fetch_verdict(request) -> "safe"|"unsafe"|"unclear".
- On "unsafe": records strike and may escalate to execute_locked / full_quarantine.
- Returns 429 on full_quarantine; otherwise lets the request proceed but emits headers:
    X-Guardrail-Decision, X-Guardrail-Mode (when applicable), X-Guardrail-Incident-ID
    Retry-After (when full_quarantine).
"""

from __future__ import annotations

import os
from typing import Awaitable, Callable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.abuse.engine import (
    AbuseConfig,
    AbuseEngine,
    Decision,
    Subject,
    decision_headers,
    generate_incident_id,
)


# ----------------------- test hook (monkeypatched in tests) -------------------
def fetch_verdict(request: Request) -> str:
    """
    Pluggable verdict fetcher. Tests monkeypatch this to return "unsafe".
    Default is "unclear" (no strike).
    """
    return "unclear"


# ----------------------- helpers ---------------------------------------------
def _hash(s: str) -> str:
    import hashlib as _h

    return _h.sha256(s.encode("utf-8")).hexdigest()


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


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


# ----------------------- middleware ------------------------------------------
class AbuseGateMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Callable,
        *,
        enabled: Optional[bool] = None,
        engine: Optional[AbuseEngine] = None,
        cfg: Optional[AbuseConfig] = None,
    ) -> None:
        super().__init__(app)
        self.enabled = _enabled("ABUSE_GATE_ENABLED", True) if enabled is None else enabled
        self.engine = engine or AbuseEngine(cfg=cfg or AbuseConfig.from_env())

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Build subject identity (hashed)
        api_key_raw = _api_key_from_headers(request)
        ip = _client_ip(request) or "0.0.0.0"
        sub = Subject(api_key_hash=_hash(api_key_raw) if api_key_raw else "anon", ip_hash=_hash(ip))

        # If already quarantined, short-circuit to 429 with headers
        mode_now = self.engine.current_mode(sub)
        if mode_now == "full_quarantine":
            return self._quarantine_response(sub, mode_now)

        # Let the (pluggable) verifier decide intent for this request
        verdict = fetch_verdict(request)  # "safe" | "unsafe" | "unclear"

        decision: Decision = "allow"
        if verdict == "unsafe":
            decision = self.engine.record_unsafe(sub)
            if decision == "full_quarantine":
                return self._quarantine_response(sub, decision)

        # Otherwise, let the request proceed; attach decision headers
        resp = await call_next(request)
        inc = generate_incident_id()
        hdrs = decision_headers(decision, inc, None)
        for k, v in hdrs.items():
            resp.headers[k] = v
        return resp

    # ------------------- helpers -------------------

    def _quarantine_response(self, sub: Subject, mode: Decision) -> JSONResponse:
        inc = generate_incident_id()
        retry = self.engine.retry_after_seconds(sub)
        hdrs = decision_headers(mode, inc, retry_after_s=retry)
        payload = {
            "code": "guardrail_quarantined",
            "detail": "access temporarily blocked due to harmful activity",
            "mode": mode,
            "retry_after_seconds": retry,
            "incident_id": inc,
        }
        resp = JSONResponse(payload, status_code=429)
        for k, v in hdrs.items():
            resp.headers[k] = v
        return resp
