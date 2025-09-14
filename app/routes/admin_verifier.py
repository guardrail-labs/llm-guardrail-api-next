from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from app.services.verifier.provider_router import VerifierRouter

# Minimal admin router for verifier; included via auto-discovery in app.main
router = APIRouter(prefix="/admin/verifier", tags=["admin"])

# Process-wide reference to the active router (may be injected by app startup code)
_ROUTER: Optional[VerifierRouter] = None


def set_router(router: VerifierRouter) -> None:
    """
    Optional helper for wiring: callers can inject the active VerifierRouter.
    Safe no-op in tests if unused.
    """
    global _ROUTER
    _ROUTER = router
