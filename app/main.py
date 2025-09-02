from __future__ import annotations

import importlib
import os
import pkgutil
import time
from typing import List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.middleware.request_id import RequestIDMiddleware, get_request_id
from app.middleware.rate_limit import RateLimitMiddleware
from app.telemetry.tracing import TracingMiddleware

try:
    # Optional but present in tests environment
    from prometheus_client import Histogram
except Exception:  # pragma: no cover
    Histogram = None  # type: ignore


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add basic security headers expected by tests."""

    async def dispatch(self, request: StarletteRequest, call_next):
        resp: StarletteResponse = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "interest-cohort=()")
        return resp


# Lightweight latency histogram so /metrics exposes guardrail_latency_seconds_*.
# No labels required for the tests.
_REQUEST_LATENCY = None
if Histogram is not None:  # pragma: no cover - exercised indirectly by tests
    _REQUEST_LATENCY = Histogram(
        "guardrail_latency_seconds", "Request latency in seconds"
    )


class _LatencyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        start = time.perf_counter()
        try:
            return await call_next(request)
        finally:
            if _REQUEST_LATENCY is not None:
                _REQUEST_LATENCY.observe(max(time.perf_counter() - start, 0.0))


def _include_all_route_modules(app: FastAPI) -> int:
    """
    Import all submodules under app.routes and include any APIRouter objects
    they define (whatever they are named).
    """
    try:
        routes_pkg = importlib.import_module("app.routes")
    except Exception:
        return 0

    count = 0
    for m in pkgutil.iter_modules(routes_pkg.__path__, routes_pkg.__name__ + "."):
        try:
            mod = importlib.import_module(m.name)
        except Exception:
            continue
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, APIRouter):
                app.include_router(obj)
                count += 1
    return count


def _status_code_to_code(status: int) -> str:
    if status == 401:
        return "unauthorized"
    if status == 404:
        return "not_found"
    if status == 413:
        return "payload_too_large"
    if status == 429:
        return "rate_limited"
    return "internal_error"


def _json_error(detail: str, status: int) -> JSONResponse:
    return JSONResponse(
        {
            "code": _status_code_to_code(status),
            "detail": detail,
            "request_id": get_request_id() or "",
        },
        status_code=status,
    )


def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api")

    # Request ID first so handlers/middleware can use it.
    app.add_middleware(RequestIDMiddleware)

    # Optional tracing
    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)

    # Rate limiting (internally env-controlled)
    app.add_middleware(RateLimitMiddleware)

    # Security headers + latency histogram
    app.add_middleware(_SecurityHeadersMiddleware)
    app.add_middleware(_LatencyMiddleware)

    # CORS
    raw_origins = (os.getenv("CORS_ALLOW_ORIGINS") or "*").split(",")
    origins: List[str] = [o.strip() for o in raw_origins if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            allow_credentials = False
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Include every APIRouter found under app.routes.*
    _include_all_route_modules(app)

    # Fallback /health (routers may also provide a richer one)
    @app.get("/health")
    async def _health_fallback():
        # Minimal shape; some tests only check .status == "ok"
        return {"status": "ok", "ok": True}

    # ---- JSON error handlers with request_id ----

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        # Preserve original detail text (e.g., "Unauthorized", "Not Found")
        return _json_error(str(exc.detail), exc.status_code)

    @app.exception_handler(Exception)
    async def _internal_exc_handler(request: Request, exc: Exception):
        # Generic 500 with JSON body so tests can .json() it.
        return _json_error("Internal Server Error", 500)

    return app


# Back-compat for tests/scripts
build_app = create_app
app = create_app()
