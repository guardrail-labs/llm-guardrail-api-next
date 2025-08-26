from fastapi import FastAPI

from app.config import settings
from app.routes.guardrail import router as guardrail_router
from app.routes.health import router as health_router
from app.telemetry.logging import setup_logging
from app.telemetry.metrics import setup_metrics


def build_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=getattr(settings, "APP_VERSION", "0.3.0"),
        description=(
            "LLM Guardrail API — secure-by-default gateway that evaluates prompts/output "
            "against basic heuristics (injection, secrets, encoded blobs)."
        ),
        contact={"name": "Maintainers", "url": "https://github.com"},
        license_info={"name": "MIT"},
    )

    app.include_router(health_router, tags=["health"])
    app.include_router(guardrail_router, tags=["guardrail"])

    # Observability
    setup_metrics(app)
    setup_logging(app)

    return app


app = build_app()
