from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, status

from app.config import admin_token
from app.services import policy, runtime_flags
from app.services.policy_loader import reload_now as _reload_now

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(request: Request) -> None:
    token = admin_token()
    auth = request.headers.get("Authorization")
    if not token or not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    provided = auth.split(" ", 1)[1]
    if provided != token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.get("/flags")
async def get_flags(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    return {"ok": True, "flags": runtime_flags.effective()}


@router.post("/flags")
async def set_flags(request: Request, payload: Dict[str, Any]) -> Dict[str, Any]:
    _require_admin(request)
    updated, errors = runtime_flags.set_many(payload or {})
    if errors:
        raise HTTPException(status_code=400, detail=errors)
    return {"ok": True, "updated": updated, "flags": runtime_flags.effective()}


@router.post("/policy/reload")
async def policy_reload(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    meta = policy.reload_rules()
    try:
        blob = _reload_now()
        version = str(blob.version)
    except Exception:
        version = str(meta.get("version"))
    return {
        "ok": True,
        "version": version,
        "rules_count": int(meta.get("rules_count", 0)),
    }


@router.get("/snapshot")
async def snapshot(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    flags = runtime_flags.effective()
    return {
        "policy_version": str(policy.current_rules_version()),
        "features": {
            "pdf_detector": bool(flags["pdf_detector_enabled"]),
            "docx_detector": bool(flags["docx_detector_enabled"]),
            "image_safe_transform": bool(flags["image_safe_transform_enabled"]),
        },
        "flags": flags,
    }
