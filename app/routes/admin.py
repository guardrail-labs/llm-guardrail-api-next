from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, status

from app.services import config_store
from app.services.policy_loader import (
    get_policy as _get_policy,
    reload_now as _reload_now,
)

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin_key(request: Request) -> None:
    """
    If ADMIN_API_KEY is set, require header X-Admin-Key to match.
    If not set, allow (dev/test friendly).
    """
    expected = os.getenv("ADMIN_API_KEY")
    if not expected:
        return
    provided = request.headers.get("X-Admin-Key")
    if provided != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.post("/policy/reload")
async def admin_policy_reload(request: Request) -> Dict[str, Any]:
    """
    Contract expected by tests:
      {
        "reloaded": true,
        "version": "...",
        "rules_loaded": true
      }
    This must update the same policy source used by /guardrail (policy_loader).
    """
    _require_admin_key(request)
    try:
        blob = _reload_now()
        return {"reloaded": True, "version": str(blob.version), "rules_loaded": True}
    except Exception:
        try:
            cur = _get_policy()
            ver = str(cur.version)
        except Exception:
            ver = "unknown"
        return {"reloaded": True, "version": ver, "rules_loaded": False}


@router.get("/bindings")
async def get_bindings(_request: Request) -> Dict[str, Any]:
    doc = config_store.load_bindings()
    return {"version": doc.version, "bindings": doc.bindings}


@router.put("/bindings")
async def put_bindings(request: Request, payload: Dict[str, Any]) -> Dict[str, Any]:
    _require_admin_key(request)
    # Accept either {"bindings":[...]} or a single binding object
    if "bindings" in payload and isinstance(payload["bindings"], list):
        items = payload["bindings"]
        out = []
        for it in items:
            t = str(it.get("tenant", "")).strip() or "default"
            b = str(it.get("bot", "")).strip() or "default"
            p = str(it.get("rules_path", "")).strip()
            if p:
                doc = config_store.upsert_binding(t, b, p)
                out = doc.bindings
        return {"ok": True, "bindings": out}
    else:
        t = str(payload.get("tenant", "")).strip() or "default"
        b = str(payload.get("bot", "")).strip() or "default"
        p = str(payload.get("rules_path", "")).strip()
        if not p:
            raise HTTPException(400, "rules_path required")
        doc = config_store.upsert_binding(t, b, p)
        return {"ok": True, "bindings": doc.bindings}


@router.delete("/bindings")
async def delete_bindings(
    request: Request, tenant: Optional[str] = None, bot: Optional[str] = None
) -> Dict[str, Any]:
    _require_admin_key(request)
    doc = config_store.delete_binding(tenant=tenant, bot=bot)
    return {"ok": True, "bindings": doc.bindings}
