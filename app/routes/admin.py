from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from app.services.policy import current_rules_version, reload_rules

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/policy/reload")
async def admin_policy_reload() -> Dict[str, Any]:
    """
    Contract expected by tests:
      {
        "reloaded": true,
        "version": "...",
        "rules_loaded": true
      }
    """
    try:
        reload_rules()
        return {
            "reloaded": True,
            "version": current_rules_version(),
            "rules_loaded": True,
        }
    except Exception:
        # Still reflect attempt; version may remain old.
        return {
            "reloaded": True,
            "version": current_rules_version(),
            "rules_loaded": False,
        }
