from __future__ import annotations

import importlib
import os
from dataclasses import asdict
from typing import Any, Dict, Optional

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.services.policy_lint import lint_policy
from app.services.policy_validate_enforce import enforcement_mode

router = APIRouter()


def _load_require_admin():
    """
    Try known modules for a shared admin guard.
    """
    for mod_name, fn_name in (
        ("app.routes.admin_rbac", "require_admin"),
        ("app.security.admin_auth", "require_admin"),
        ("app.routes.admin_common", "require_admin"),
        ("app.security.admin", "require_admin"),
        ("app.security.auth", "require_admin"),
    ):
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:
            continue
    return None


def _settings_admin_key(request: Request) -> Optional[str]:
    """
    Best-effort read of the settings-based admin key used by other admin routes.
    """
    try:
        settings = getattr(request.app.state, "settings", None)
        admin = getattr(settings, "admin", None)
        key = getattr(admin, "key", None)
        if key:
            return str(key)
    except Exception:
        pass
    return None


def _require_admin_dep(request: Request):
    """
    Enforce admin auth for policy validation:
    - Prefer project-wide require_admin() if present.
    - Else require X-Admin-Key matching ENV first, then settings.admin.key (env has priority).
    """
    guard = _load_require_admin()
    if callable(guard):
        guard(request)
        return

    env_key = os.getenv("ADMIN_API_KEY") or os.getenv("GUARDRAIL_ADMIN_KEY")
    cfg_key = _settings_admin_key(request)
    required = env_key or cfg_key
    if required:
        supplied = request.headers.get("X-Admin-Key")
        if str(supplied) != str(required):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    # If no key configured anywhere, allow (legacy behavior).


@router.post("/admin/api/policy/validate", dependencies=[Depends(_require_admin_dep)])
async def policy_validate(payload: Dict[str, Any] = Body(...)) -> JSONResponse:
    text = payload.get("yaml") or payload.get("text") or ""
    from app.services.policy_validate import validate_yaml_text

    result = validate_yaml_text(str(text))

    policy_obj: Any | None = payload.get("policy")
    if policy_obj is None and text:
        try:
            policy_obj = yaml.safe_load(str(text))
        except Exception:
            policy_obj = None

    lint_items = lint_policy(policy_obj) if policy_obj is not None else []
    lint_dicts = [asdict(item) for item in lint_items]
    result["lints"] = lint_dicts

    mode = enforcement_mode()
    result["enforcement_mode"] = mode
    status_value = result.get("status", "ok")
    has_lint_error = any(item.get("severity") == "error" for item in lint_dicts)
    if mode == "block" and has_lint_error:
        status_value = "fail"
        result["status"] = "fail"

    try:
        from prometheus_client import Counter  # pragma: no cover

        counter = Counter(
            "guardrail_policy_validate_total",
            "Policy validation runs by status",
            ["status"],
        )
        counter.labels(status=result["status"]).inc()
    except Exception:  # pragma: no cover - metrics optional
        pass

    status_code = (
        status.HTTP_200_OK if status_value == "ok" else status.HTTP_422_UNPROCESSABLE_ENTITY
    )
    return JSONResponse(result, status_code=status_code)
