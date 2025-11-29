from __future__ import annotations

from typing import Dict

from fastapi import APIRouter

from app.services.license import license_state, refresh_license_from_remote
from app.settings import get_settings

router = APIRouter(tags=["license"])


@router.get("/license/validate")
async def validate_license() -> Dict[str, object]:
    """
    Return the current license status from the in-memory license_state.

    In future phases this endpoint may also trigger a fresh check against the
    central license verification service when appropriate.
    """
    settings = get_settings()

    if settings.guardrail_license_key and settings.license_verify_url:
        await refresh_license_from_remote(
            license_key=settings.guardrail_license_key,
            verify_url=settings.license_verify_url,
            timeout_seconds=settings.license_verify_timeout_seconds,
            instance_id=getattr(settings, "instance_id", None),
            runtime="core",
        )

    status = license_state.get()
    return status.as_dict()
