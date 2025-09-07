from __future__ import annotations
from fastapi import APIRouter

from app.telemetry.metrics import (
    get_requests_total,
    get_decisions_total,
    get_rules_version,
)

router = APIRouter(prefix="/health", tags=["system"])


@router.get("")
def health() -> dict:
    return {
        "ok": True,
        "status": "ok",
        "requests_total": float(get_requests_total()),
        "decisions_total": float(get_decisions_total()),
        "rules_version": str(get_rules_version()),
    }
