import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.middleware.auth import AuthMiddleware
from app.middleware.ratelimit import RateLimitMiddleware
from app.middleware.headers import SecurityHeadersMiddleware
from app.routes.guardrail import router as guardrail_router
from app.routes.health import router as health_router
from app.routes.output import router as output_router
from app.routes.policy_admin import router as policy_router
from app.telemetry.errors import register_error_handlers
from app.telemetry.logging import setup_logging
from app.telemetry.metrics import setup_metrics
from app.telemetry.tracing import RequestIDMiddleware


def build_app() -> FastAPI:
    _ = get_settings()  # ensure settings loaded
    app = FastAPI(
        title="llm-guardrail-api-next",
        version="0.3.0",
        description=(
            "LLM Guardrail API — secure-by-default gateway that evaluates prompts/output "
            "against basic heuristics (injection, secrets, encoded blobs)."
        ),
        contact={"name": "Maintainers", "url": "https://github.com"},
        license_info={"name": "MIT"},
    )

    origins_env = os.environ.get("CORS_ALLOW_ORIGINS", "*")
    origins = ["*"] if origins_env.strip() == "*" else [
        o.strip() for o in origins_env.split(",") if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Observability + security middlewares
    app.add_middleware(RequestIDMiddleware)   # sets/echoes X-Request-ID
    app.add_middleware(AuthMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # Routers
    app.include_router(health_router, tags=["health"])
    app.include_router(guardrail_router, tags=["guardrail"])
    app.include_router(output_router, tags=["guardrail"])
    app.include_router(policy_router, tags=["policy"])  # admin endpoints

    # Metrics & structured request logging
    setup_metrics(app)
    setup_logging(app)

    # Global JSON error handlers
    register_error_handlers(app)

    return app


app = build_app()
