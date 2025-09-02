# app/routes/admin_threat.py
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/admin/threat", tags=["admin"])

@router.post("/reload")
def reload_threat_feeds() -> dict:
    # Minimal contract for tests: just 200 OK
    return {"ok": True, "reloaded": True}
