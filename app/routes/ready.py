from __future__ import annotations
from fastapi import APIRouter
from app.config import get_settings

router = APIRouter(prefix="/ready", tags=["system"])

@router.get("", summary="Readiness probe")
def ready() -> dict:
    s = get_settings()
    return {
        "ok": True,
        "status": "ready",
        "version": s.VERSION,
        "git_sha": s.GIT_SHA,
        "env": s.ENV,
    }
