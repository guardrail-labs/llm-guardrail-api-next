from __future__ import annotations
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.telemetry.logging import configure_logging
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.access_log import AccessLogMiddleware

# Routers
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router
from app.routes.health import router as health_router
from app.routes.admin import router as admin_router
from app.routes.ready import router as ready_router

# Optional imports (rate limiter, latency)
try:
    from app.middleware.rate_limit import RateLimitMiddleware  # type: ignore
except Exception:  # pragma: no cover
    RateLimitMiddleware = None  # type: ignore

try:
    from app.telemetry.latency import LatencyHistogramMiddleware  # type: ignore
except Exception:  # pragma: no cover
    LatencyHistogramMiddleware = None  # type: ignore


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging()

    app = FastAPI(title=s.APP_NAME)

    # CORS (handle wildcard + credentials constraint)
    origins_raw = (s.CORS_ALLOW_ORIGINS or "").strip()
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            allow_credentials = False  # Starlette constraint
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

    # Optional latency histogram
    if LatencyHistogramMiddleware is not None and s.ENABLE_LATENCY_HISTOGRAM:
        app.add_middleware(LatencyHistogramMiddleware)

    # Optional rate limiter (uses your existing settings fields)
    if RateLimitMiddleware is not None and s.RATE_LIMIT_ENABLED:
        app.add_middleware(RateLimitMiddleware)

    # Routers
    app.include_router(health_router)
    app.include_router(ready_router)
    app.include_router(admin_router)
    app.include_router(metrics_router)
    app.include_router(oai_router)
    app.include_router(azure_router)

    # Error handlers (preserve your existing contracts)
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": "not_found" if exc.status_code == 404 else "error",
                "detail": exc.detail,
                "request_id": rid,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "detail": "internal error", "request_id": rid},
        )

    return app


def build_app() -> FastAPI:  # pragma: no cover
    return create_app()


app = create_app()
