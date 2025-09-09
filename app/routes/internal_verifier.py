from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Query

from app.services.verifier import get_ops_overview

router = APIRouter(prefix="/internal/verifier", tags=["internal"])


@router.get("/scoreboard")
async def get_scoreboard(
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    x_internal_auth: Optional[str] = Header(
        default=None, alias="X-Internal-Auth", convert_underscores=False
    ),
) -> Dict[str, Any]:
    """
    Lightweight internal scoreboard. Optional header guard:
    if env INTERNAL_AUTH is set by ops, require clients to send the same value.
    """
    import os

    want = (os.getenv("INTERNAL_AUTH") or "").strip()
    if want and (x_internal_auth or "").strip() != want:
        raise HTTPException(status_code=403, detail="forbidden")

    # No secrets/PII; the snapshot is safe for internal dashboards.
    return get_ops_overview(tenant=tenant, bot=bot)
