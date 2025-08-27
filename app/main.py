from __future__ import annotations

from fastapi import FastAPI

from app.config import get_settings
from app.middleware.auth import APIKeyAuthMiddleware  # renamed class
from app.middleware.headers import SecurityHeadersMiddleware
from app.middleware.ratelimit import RateLimitMiddleware
from app.telemetry.logging import json_access_log
from app.telemetry.metrics import metrics_middleware, metrics_route
from app.telemetry.tracing import TracingMiddleware
from app.routes.guardrail import router as guardrail_router
from app.routes.output import router as output_router
from app.routes.health import router as health_router
from app.routes.admin import router as admin_router


def build_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="llm-guardrail-api-next")

    # Middleware order: logging/metrics/security/ratelimit/tracing, then auth last
    app.middleware("http")(json_access_log)
    app.middleware("http")(metrics_middleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(TracingMiddleware)

    # Auth (configured to allowlist /health and /metrics internally)
    app.add_middleware(APIKeyAuthMiddleware)

    # Routes
    app.include_router(health_router)
    app.include_router(guardrail_router)
    app.include_router(output_router)
    app.include_router(admin_router)

    # Metrics endpoint
    app.add_route("/metrics", metrics_route, methods=["GET"])

    return app


app = build_app()
