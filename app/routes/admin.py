from fastapi import APIRouter

from app.services.policy import force_reload

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/policy/reload")
def reload_policy() -> dict:
    """
    Manually reload the policy rules file and return the new version.
    Protected by your global auth middleware (tests send X-API-Key).
    """
    version = force_reload()
    return {"reloaded": True, "version": version}
