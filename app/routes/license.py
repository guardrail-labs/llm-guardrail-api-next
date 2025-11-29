from __future__ import annotations

from typing import Dict

from fastapi import APIRouter

from app.services.license import license_state

router = APIRouter(tags=["license"])


@router.get("/license/validate")
async def validate_license() -> Dict[str, object]:
    """
    Return the current license status from the in-memory license_state.

    In future phases this endpoint may also trigger a fresh check against the
    central license verification service when appropriate.
    """
    status = license_state.get()
    return status.as_dict()
