from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request

from app.middleware.quota import QuotaMiddleware

router = APIRouter(prefix="/admin/quota", tags=["admin-quota"])


def _find_quota_middleware(app) -> Optional[QuotaMiddleware]:
    """
    Walk the middleware stack to locate the QuotaMiddleware instance.
    """
    stack = getattr(app, "middleware_stack", None)
    node = stack
    # BaseHTTPMiddleware creates a linked list via .app
    visited = 0
    while node is not None and visited < 50:
        if isinstance(node, QuotaMiddleware):
            return node
        node = getattr(node, "app", None)
        visited += 1
    return None


@router.get("/status")
async def quota_status(request: Request, key: str = Query(..., min_length=1)) -> Dict[str, Any]:
    mw = _find_quota_middleware(request.app)
    if mw is None:
        raise HTTPException(status_code=503, detail="Quota middleware not available")

    status = mw.store.peek(key)
    return {
        "enabled": bool(mw.enabled),
        "limits": {"per_day": int(mw.per_day), "per_month": int(mw.per_month)},
        "status": status,
    }


@router.post("/reset")
async def quota_reset(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    key = str(payload.get("key") or "").strip()
    scope = str(payload.get("scope") or "both").strip().lower()
    if not key:
        raise HTTPException(status_code=400, detail="Missing 'key'")

    if scope not in ("day", "month", "both"):
        raise HTTPException(status_code=400, detail="Invalid 'scope'")

    mw = _find_quota_middleware(request.app)
    if mw is None:
        raise HTTPException(status_code=503, detail="Quota middleware not available")

    mw.store.reset_key(key, which=scope)
    status = mw.store.peek(key)
    return {
        "ok": True,
        "scope": scope,
        "limits": {"per_day": int(mw.per_day), "per_month": int(mw.per_month)},
        "status": status,
    }

