from __future__ import annotations

import os
import uuid
from typing import Optional, Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.middleware.access_log import AccessLogMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.telemetry.logging import configure_logging

# Routers
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router
from app.routes.health import router as health_router
from app.routes.admin import router as admin_router
from app.routes.ready import router as ready_router
from app.routes.guardrail import router as guardrail_router
from app.routes.output import router as output_router
from app.routes.proxy import router as proxy_router
from app.routes.batch import router as batch_router

# Optional imports (rate limiter, latency)
try:
    from app.middleware.rate_limit import RateLimitMiddleware
except Exception:  # pragma: no cover
    RateLimitMiddleware = None  # type: ignore[assignment]

try:
    from app.telemetry.latency import LatencyHistogramMiddleware
except Exception:  # pragma: no cover
    LatencyHistogramMiddleware = None  # type: ignore[assignment]

# Optional tracing (alias variable so we don't assign to a type)
try:
    from app.telemetry.tracing import TracingMiddleware as TracingMiddlewareCls
except Exception:  # pragma: no cover
    TracingMiddlewareCls = None


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging()

    app = FastAPI(title=s.APP_NAME)

    # CORS
    origins = [o.strip() for o in (getattr(s, "CORS_ALLOW_ORIGINS", "*") or "").split(",") if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            # Starlette constraint: "*" cannot be combined with allow_credentials=True
            allow_credentials = False
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Access logging first to capture everything
    app.add_middleware(AccessLogMiddleware)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Optional tracing (no-op unless OTEL_ENABLED and deps present)
    if TracingMiddlewareCls is not None and _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddlewareCls)

    # Optional latency histogram
    if LatencyHistogramMiddleware is not None and getattr(s, "ENABLE_LATENCY_HISTOGRAM", True):
        app.add_middleware(LatencyHistogramMiddleware)

    # Optional rate limiter
    if RateLimitMiddleware is not None and getattr(s, "RATE_LIMIT_ENABLED", False):
        app.add_middleware(RateLimitMiddleware)

    # Routers
    app.include_router(health_router)
    app.include_router(ready_router)
    app.include_router(admin_router)
    app.include_router(metrics_router)
    app.include_router(oai_router)
    app.include_router(azure_router)
    app.include_router(guardrail_router)
    app.include_router(output_router)
    app.include_router(proxy_router)
    app.include_router(batch_router)

    # Error handlers (preserve existing contracts)
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        # Normalize 404 and other HTTP errors per contract
        code = "not_found" if exc.status_code == 404 else "error"
        detail = exc.detail if isinstance(exc.detail, str) else "error"
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": code, "detail": detail, "request_id": rid},
            headers={"X-Request-ID": rid},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "detail": "internal error", "request_id": rid},
            headers={"X-Request-ID": rid},
        )

    return app


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


# Compatibility for tests that import build_app
build_app = create_app
app = create_app()
