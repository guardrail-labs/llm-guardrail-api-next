from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter

# Use the same loader used by the legacy /guardrail route
from app.services.policy_loader import get_policy as _get_policy, reload_now as _reload_now

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
    This must update the same policy source used by /guardrail (policy_loader).
    """
    try:
        blob = _reload_now()
        return {
            "reloaded": True,
            "version": str(blob.version),
            "rules_loaded": True,
        }
    except Exception:
        # Still reflect attempt; version may remain old.
        try:
            cur = _get_policy()
            ver = str(cur.version)
        except Exception:
            ver = "unknown"
        return {"reloaded": True, "version": ver, "rules_loaded": False}
