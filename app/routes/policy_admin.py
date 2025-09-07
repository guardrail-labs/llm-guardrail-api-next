from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, status

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


@router.post("/admin/policy/reload")
def policy_reload():
    blob = reload_now()
    return {"reloaded": True, "version": blob.version, "rules_path": blob.path}


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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )

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
