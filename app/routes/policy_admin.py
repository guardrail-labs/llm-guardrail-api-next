from __future__ import annotations

from fastapi import APIRouter, Depends

from app.middleware.auth import require_api_key
from app.services.policy_loader import get_policy, reload_now

# No prefix; use absolute paths in decorators to avoid surprises
router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/policy/version")
def policy_version():
    blob = get_policy()
    return {
        "version": blob.version,
        "rules_path": blob.path,
        "mtime": blob.mtime,
        # Reflects runtime via env; shown here as informational
        "autoreload": True,
    }


@router.post("/admin/policy/reload")
def policy_reload():
    blob = reload_now()
    return {"reloaded": True, "version": blob.version, "rules_path": blob.path}
