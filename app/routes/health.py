from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from app.services.policy import current_rules_version

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> Dict[str, Any]:
    """
    Contract expected by tests:
      {
        "ok": true,
        "status": "ok",
        "requests_total": float,
        "decisions_total": float,
        "rules_version": "..."
      }
    """
    # Import lazily to avoid hard dependency if legacy guardrail is not present.
    requests_total = 0.0
    decisions_total = 0.0
    try:
        from app.routes.guardrail import (  # noqa: WPS433
            get_requests_total,
            get_decisions_total,
        )

        requests_total = float(get_requests_total())
        decisions_total = float(get_decisions_total())
    except Exception:
        # Keep zeros if legacy counters aren't available.
        pass

    return {
        "ok": True,
        "status": "ok",
        "requests_total": requests_total,
        "decisions_total": decisions_total,
        "rules_version": current_rules_version(),
    }
