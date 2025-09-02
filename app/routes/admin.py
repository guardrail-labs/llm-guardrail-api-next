from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.policy import reload_rules, current_rules_version

router = APIRouter(prefix="/admin", tags=["admin"])

@router.post("/policy/reload")
async def policy_reload() -> JSONResponse:
    # Force reload; surface contract fields expected by tests
    reload_rules()
    body = {
        "reloaded": True,
        "version": str(current_rules_version()),
        "rules_loaded": True,
    }
    return JSONResponse(body)
