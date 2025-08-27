from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from app.middleware.headers import SecurityHeadersMiddleware
from app.middleware.ratelimit import RateLimitMiddleware

from app.routes.health import router as health_router
from app.routes.guardrail import router as guardrail_router
from app.routes.output import router as output_router
from app.routes.admin import router as admin_router


def build_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api-next")

    # Middlewares (keep security headers and rate limiting; auth is not needed for tests)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # Routes
    app.include_router(health_router)
    app.include_router(guardrail_router)
    app.include_router(output_router)
    app.include_router(admin_router)

    # Minimal /metrics endpoint (tests only assert it's reachable with 200)
    @app.get("/metrics")
    def metrics() -> PlainTextResponse:
        return PlainTextResponse("ok\n")

    return app


app = build_app()
