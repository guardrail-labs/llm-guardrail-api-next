from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, status

from app.config import admin_token
from app.services import policy
from app.services.policy_loader import get_policy, reload_now

# No prefix; use absolute paths in decorators to avoid surprises
router = APIRouter()


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


def _require_admin(request: Request) -> None:
    token = admin_token()
    auth = request.headers.get("Authorization")
    if not token or not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    provided = auth.split(" ", 1)[1]
    if provided != token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.post("/admin/policy/reload")
def policy_reload(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    meta = policy.reload_rules()
    try:
        blob = reload_now()
        version = str(blob.version)
    except Exception:
        version = str(meta.get("version"))
    return {
        "ok": True,
        "version": version,
        "rules_count": int(meta.get("rules_count", 0)),
    }


@router.get("/admin/bindings/resolve")
def bindings_resolve(request: Request, tenant: str = "default", bot: str = "default"):
    """
    Introspect which rules pack is active for a given (tenant, bot).
    Returns the resolved rules_path and current policy_version.
    Honors optional admin auth via X-Admin-Key if ADMIN_API_KEY is set.
    """
    admin_key = os.getenv("ADMIN_API_KEY") or ""
    if admin_key:
        provided = request.headers.get("X-Admin-Key") or ""
        if provided != admin_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Resolve using the same loader logic used by enforcement.
    # We set the binding context temporarily for this request and read the policy blob.
    from app.services.policy_loader import set_binding_context as _set_ctx

    _set_ctx(tenant, bot)
    blob = get_policy()

    # Reset binding context to defaults to avoid side effects across requests.
    _set_ctx("default", "default")

    # Keep response minimal and stable for tests/CI.
    return {
        "tenant": tenant,
        "bot": bot,
        "rules_path": blob.path,
        "policy_version": str(blob.version),
    }
