from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.middleware.ratelimit import RateLimitMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.routes.guardrail import router as guardrail_router
from app.routes.health import router as health_router
from app.routes.output import router as output_router
from app.telemetry.logging import setup_logging
from app.telemetry.metrics import setup_metrics
from app.telemetry.tracing import RequestIDMiddleware


def build_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "LLM Guardrail API — secure-by-default gateway that evaluates prompts/output "
            "against basic heuristics (injection, secrets, encoded blobs)."
        ),
        contact={"name": "Maintainers", "url": "https://github.com"},
        license_info={"name": "MIT"},
    )

    origins = ["*"] if settings.CORS_ALLOW_ORIGINS.strip() == "*" else [
        o.strip() for o in settings.CORS_ALLOW_ORIGINS.split(",") if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health_router, tags=["health"])
    app.include_router(guardrail_router, tags=["guardrail"])
    app.include_router(output_router, tags=["guardrail"])

    setup_metrics(app)
    setup_logging(app)

    return app


app = build_app()

