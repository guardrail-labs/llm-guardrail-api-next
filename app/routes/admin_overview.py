from __future__ import annotations

import hashlib
import importlib
import json
import os
from typing import Any, Dict, Mapping, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/ui/templates")


# ---- Admin guard (reuse the same resolution policy as decisions router)
def _load_require_admin() -> Optional[Any]:
    env = os.getenv("ADMIN_GUARD")
    if env:
        mod_name, _, fn_name = env.partition(":")
        fn_name = fn_name or "require_admin"
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:
            pass
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


def _require_admin_dep(request: Request):
    guard = _load_require_admin()
    if callable(guard):
        guard(request)
    settings = getattr(request.app.state, "settings", None)
    admin_settings = getattr(settings, "admin", None)
    cfg_key = (
        os.getenv("ADMIN_API_KEY")
        or os.getenv("GUARDRAIL_ADMIN_KEY")
        or getattr(admin_settings, "key", None)
    )
    if cfg_key:
        supplied = request.headers.get("X-Admin-Key") or request.query_params.get("admin_key")
        if str(supplied) != str(cfg_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authentication required",
            )
    return None


router = APIRouter(dependencies=[Depends(_require_admin_dep)])


# ---- Policy helpers
def _get_merged_policy() -> Dict[str, Any]:
    """
    Return the effective merged policy as a plain dict.
    Prefers policy.get_active_policy(); falls back to policy.get() if present.
    """
    try:
        from app.services import policy as pol

        data = None
        if hasattr(pol, "get_active_policy"):
            data = pol.get_active_policy()
        elif hasattr(pol, "get"):
            # legacy alias, if still present
            data = pol.get()

        if isinstance(data, Mapping):
            return dict(data)
        if data:
            return dict(cast(Dict[str, Any], data))
    except Exception:
        pass
    return {}


def _policy_version_id(merged: Dict[str, Any]) -> str:
    """
    Prefer policy.current_rules_version(); fallback to a short SHA-256 of the merged doc.
    """
    try:
        from app.services import policy as pol

        if hasattr(pol, "current_rules_version"):
            ver = pol.current_rules_version()
            if ver:
                return str(ver)
    except Exception:
        pass

    # Fallback: stable-ish short hash of merged policy
    if not merged:
        return "none"
    try:
        b = json.dumps(merged, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(b).hexdigest()[:12]
    except Exception:
        return "unknown"


_SENSITIVE_KEYS = ("secret", "token", "password", "key", "private", "credential", "auth")


def _redact(val: Any) -> Any:
    if isinstance(val, dict):
        out: Dict[str, Any] = {}
        for k, v in val.items():
            if any(s in str(k).lower() for s in _SENSITIVE_KEYS):
                out[k] = "***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(val, list):
        return [_redact(item) for item in val]
    return val


# ---- Pages
@router.get("/admin", response_class=HTMLResponse)
async def admin_overview(request: Request):
    merged = _get_merged_policy()
    version = _policy_version_id(merged)
    return templates.TemplateResponse(
        "admin_overview.html",
        {
            "request": request,
            "policy_version": version,
        },
    )


@router.get("/admin/policy/current", response_class=HTMLResponse)
async def policy_current(request: Request):
    merged = _get_merged_policy()
    redacted = _redact(merged)
    try:
        import yaml  # if unavailable, JSON fallback below still works

        yaml_text = yaml.safe_dump(redacted, sort_keys=True, default_flow_style=False)
        fmt = "yaml"
        text = yaml_text
    except Exception:
        text = json.dumps(redacted, indent=2, sort_keys=True)
        fmt = "json"
    version = _policy_version_id(merged)
    return templates.TemplateResponse(
        "policy_view.html",
        {
            "request": request,
            "policy_version": version,
            "format": fmt,
            "body": text,
        },
    )
