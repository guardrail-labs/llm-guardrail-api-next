from __future__ import annotations

import os
import time
import uuid
import importlib
from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

# Routers (keep imports at top per E402)
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router
from app.routes.health import router as health_router
from app.routes.admin import router as admin_router

if TYPE_CHECKING:
    from fastapi import APIRouter


# -----------------------------
# Latency histogram middleware
# -----------------------------
try:
    from app.telemetry.latency import GuardrailLatencyMiddleware
except Exception:  # pragma: no cover
    GuardrailLatencyMiddleware = None  # type: ignore[assignment]


# -----------------------------
# Simple auth guard for /proxy/*
# -----------------------------
class _AuthProxyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        if path.startswith("/proxy/"):
            if not (request.headers.get("X-API-Key") or request.headers.get("Authorization")):
                rid = getattr(request.state, "request_id", "") or str(uuid.uuid4())
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized", "request_id": rid},
                    headers={
                        "WWW-Authenticate": "Bearer",
                        "X-Request-ID": rid,
                    },
                )
        return await call_next(request)


# -----------------------------
# Request ID + security headers (outermost)
# -----------------------------
class _RequestIdAndSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = rid
        resp = await call_next(request)
        # Always attach headers
        resp.headers.setdefault("X-Request-ID", rid)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-XSS-Protection", "0")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp


# -----------------------------
# Optional routers (legacy)
# -----------------------------
guardrail_router: Optional["APIRouter"] = None
threat_admin_router: Optional["APIRouter"] = None
proxy_router: Optional["APIRouter"] = None
batch_router: Optional["APIRouter"] = None
output_router: Optional["APIRouter"] = None

try:  # pragma: no cover
    from app.routes.guardrail import router as _guardrail_router
    from app.routes.guardrail import threat_admin_router as _threat_admin_router

    guardrail_router = _guardrail_router
    threat_admin_router = _threat_admin_router
except Exception:  # pragma: no cover
    pass

try:  # pragma: no cover
    from app.routes.proxy import router as _proxy_router

    proxy_router = _proxy_router
except Exception:  # pragma: no cover
    pass

try:  # pragma: no cover
    from app.routes.batch import router as _batch_router

    batch_router = _batch_router
except Exception:  # pragma: no cover
    pass

try:  # pragma: no cover
    from app.routes.output import router as _output_router

    output_router = _output_router
except Exception:  # pragma: no cover
    pass


def _create_app() -> FastAPI:
    app = FastAPI(title="LLM Guardrail API", version="next")

    # --- CORS (optional) ---
    allow_origins = (os.environ.get("CORS_ALLOW_ORIGINS") or "").strip()
    if allow_origins:
        origins = [o.strip() for o in allow_origins.split(",") if o.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- Latency histogram (if available) ---
    if GuardrailLatencyMiddleware is not None:
        app.add_middleware(GuardrailLatencyMiddleware)

    # --- Rate limit middleware (dynamic import, optional) ---
    try:  # pragma: no cover
        rl_mod = importlib.import_module("app.services.rate_limit")
        RL = getattr(rl_mod, "RateLimitMiddleware", None)
        if RL is not None:
            app.add_middleware(RL)
    except Exception:
        pass

    # --- Auth guard for /proxy/* ---
    app.add_middleware(_AuthProxyMiddleware)

    # --- Exception handlers (404/500 JSON contract) ---
    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code != 404:
            # let other HTTP errors bubble with request id attached
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers={"X-Request-ID": getattr(request.state, "request_id", "")},
            )
        rid = getattr(request.state, "request_id", "")
        body = {"code": "not_found", "detail": "not found", "request_id": rid}
        return JSONResponse(status_code=404, content=body, headers={"X-Request-ID": rid})

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, _: Exception):
        rid = getattr(request.state, "request_id", "")
        body = {"code": "internal_error", "detail": "internal error", "request_id": rid}
        return JSONResponse(status_code=500, content=body, headers={"X-Request-ID": rid})

    # --- Routers (public API first) ---
    app.include_router(oai_router)
    app.include_router(azure_router)

    # health + admin contract routes
    app.include_router(health_router)
    app.include_router(admin_router)

    # Optional routes if present
    if proxy_router is not None:
        app.include_router(proxy_router)
    if batch_router is not None:
        app.include_router(batch_router)
    if output_router is not None:
        app.include_router(output_router)
    if guardrail_router is not None:
        app.include_router(guardrail_router)
    if threat_admin_router is not None:
        app.include_router(threat_admin_router)

    # Prometheus /metrics
    app.include_router(metrics_router)

    # Place request-id/security OUTERMOST so it wraps everything
    app.add_middleware(_RequestIdAndSecurityMiddleware)
    return app


def build_app() -> FastAPI:  # pragma: no cover
    return _create_app()


def create_app() -> FastAPI:
    return _create_app()


app = _create_app()
