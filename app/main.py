from fastapi import FastAPI
from app.config import settings
from app.routes.health import router as health_router
from app.routes.guardrail import router as guardrail_router
from app.telemetry.metrics import setup_metrics

def build_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)
    app.include_router(health_router, tags=["health"])
    app.include_router(guardrail_router, tags=["guardrail"])
    setup_metrics(app)
    return app

app = build_app()
