from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter

# Import the same singleton the tests use to seed snapshots.
# _ROUTER is created in app.services.verifier.__init__
from app.services.verifier import _ROUTER  # noqa: F401

router = APIRouter(prefix="/admin/api/verifier", tags=["admin"])


@router.get("/router/snapshot")
async def verifier_router_snapshot() -> List[Any]:
    """
    Expose the in-process router's last order snapshot.
    Returns an empty list if the router is not initialized or an error occurs.
    """
    try:
        router_obj = _ROUTER
    except Exception:
        router_obj = None

    if router_obj is None:
        return []

    try:
        snaps = router_obj.get_last_order_snapshot()
        # Ensure we always return a list for JSON serialization.
        return snaps if isinstance(snaps, list) else list(snaps)
    except Exception:
        return []
