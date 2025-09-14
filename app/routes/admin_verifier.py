from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter
from fastapi.responses import JSONResponse

# Reuse the existing singleton created in app.services.verifier.__init__
# (Older code/tests refer to this as _ROUTER; we intentionally import it.)
try:
    from app.services.verifier import _ROUTER
except Exception:  # pragma: no cover
    _ROUTER = None 

_ROUTER = cast(Any, _ROUTER)

router = APIRouter()


@router.get("/admin/api/verifier/router/snapshot")
async def verifier_router_snapshot() -> JSONResponse:
    if _ROUTER is None:
        return JSONResponse([], status_code=200)
    try:
        snaps = _ROUTER.get_last_order_snapshot()
    except Exception:
        snaps = []
    return JSONResponse(snaps, status_code=200)
