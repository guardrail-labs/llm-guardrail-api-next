from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Awaitable, Callable, Dict, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.metrics.route_label import route_label
from app.middleware.request_id import get_request_id

RequestHandler = Callable[[Request], Awaitable[Response]]

_LOGGER_NAME = "guardrail"
_log = logging.getLogger(_LOGGER_NAME)


# ------------------------------ env helpers -----------------------------------


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(float(raw.strip()))
        return v
    except Exception:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = float(raw.strip())
        if v != v:  # NaN
            return default
        return v
    except Exception:
        return default


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


# ------------------------------- snapshot -------------------------------------


def _snapshot_payload() -> Dict[str, Any]:
    payload: Dict[str, Any] = {"event": "config_snapshot", "version": "1"}

    # Verifier settings (optional helper module)
    try:
        from app.services.config_sanitizer import (  # type: ignore
            get_verifier_latency_budget_ms,
            get_verifier_sampling_pct,
        )

        payload["verifier_latency_budget_ms"] = get_verifier_latency_budget_ms()
        payload["verifier_sampling_pct"] = get_verifier_sampling_pct()
    except Exception:
        payload["verifier_latency_budget_ms"] = None
        payload["verifier_sampling_pct"] = 0.0

    # API security (optional)
    try:
        from app.middleware.security import (  # type: ignore
            rate_limit_config,
            secured_prefixes,
            security_enabled,
        )

        payload["api_security_enabled"] = bool(security_enabled())
        rps, burst = rate_limit_config()
        payload["api_rate_limit_rps"] = rps
        payload["api_rate_limit_burst"] = burst
        payload["api_secured_prefixes"] = list(secured_prefixes())
    except Exception:
        payload["api_security_enabled"] = False

    # CORS (read envs directly; middleware installs unconditionally with env shaping)
    payload["cors_allow_origins"] = _csv_env("CORS_ALLOW_ORIGINS")
    payload["cors_allow_methods"] = _csv_env("CORS_ALLOW_METHODS") or [
        "GET",
        "POST",
        "OPTIONS",
    ]
    payload["cors_credentials"] = _bool_env("CORS_ALLOW_CREDENTIALS", False)

    # Security headers (default enabled in our build; allow opt-out)
    try:
        from app.middleware.security_headers import sec_headers_enabled  # type: ignore

        payload["security_headers_enabled"] = bool(sec_headers_enabled())
    except Exception:
        payload["security_headers_enabled"] = True

    # Max body
    payload["max_request_bytes"] = max(0, _int_env("MAX_REQUEST_BYTES", 0))
    payload["max_request_bytes_paths"] = _csv_env("MAX_REQUEST_BYTES_PATHS") or ["/"]

    return payload


def log_config_snapshot() -> None:
    snap_enabled = _bool_env("LOG_SNAPSHOT_ENABLED", _bool_env("LOG_JSON_ENABLED", False))
    if not snap_enabled:
        return
    payload = _snapshot_payload()
    payload["ts"] = int(time.time() * 1000)
    try:
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        line = '{"event":"config_snapshot","error":"serialize_failure"}'
    _log.info(line)


# ------------------------------- middleware -----------------------------------


class _JSONAccessLogMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._enabled = _bool_env(
            "LOG_REQUESTS_ENABLED",
            _bool_env("LOG_JSON_ENABLED", False),
        )
        self._prefixes = _csv_env("LOG_REQUESTS_PATHS") or ["/"]
        self._min_status = max(0, _int_env("LOG_MIN_STATUS", 0))

    def _should_log(self, path: str, status: int) -> bool:
        if not self._enabled:
            return False
        if status < self._min_status:
            return False
        return any(path.startswith(p) for p in self._prefixes)

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        start = time.perf_counter()
        resp = await call_next(request)
        try:
            dur_ms = int((time.perf_counter() - start) * 1000.0)
            path = request.url.path or "/"
            if not self._should_log(path, resp.status_code):
                return resp

            rid = get_request_id() or ""
            client = request.client.host if request.client and request.client.host else ""
            msg = {
                "event": "http_access",
                "ts": int(time.time() * 1000),
                "method": request.method,
                "path": path,
                "route": route_label(path),
                "status": resp.status_code,
                "duration_ms": dur_ms,
                "request_id": rid,
                "client_ip": client,
            }
            try:
                clen = int(request.headers.get("content-length", "0"))
                msg["request_bytes"] = max(clen, 0)
            except Exception:
                pass
            try:
                rlen = int(resp.headers.get("content-length", "0"))
                msg["response_bytes"] = max(rlen, 0)
            except Exception:
                pass

            line = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
            _log.info(line)
        except Exception:
            # Never break the request on logging issues
            pass
        return resp


def install_request_logging(app) -> None:
    # Install only if JSON logging is globally enabled or requests are explicitly enabled
    if not (_bool_env("LOG_JSON_ENABLED", False) or _bool_env("LOG_REQUESTS_ENABLED", False)):
        return
    app.add_middleware(_JSONAccessLogMiddleware)

