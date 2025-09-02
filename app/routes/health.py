from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.policy import current_rules_version

# Optional legacy counters
try:
    from app.routes.guardrail import get_requests_total, get_decisions_total
except Exception:  # pragma: no cover
    def get_requests_total() -> float:  # type: ignore[no-redef]
        return 0.0
    def get_decisions_total() -> float:  # type: ignore[no-redef]
        return 0.0

router = APIRouter(tags=["health"])

@router.get("/health")
async def health() -> JSONResponse:
    body = {
        "ok": True,
        "requests_total": float(get_requests_total()),
        "decisions_total": float(get_decisions_total()),
        "rules_version": str(current_rules_version()),
    }
    return JSONResponse(body)
