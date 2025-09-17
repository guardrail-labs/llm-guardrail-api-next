from __future__ import annotations

import hashlib
import importlib
import json
import os
from typing import Any, Dict, List, Mapping, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/ui/templates")


def _load_require_admin():
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


class PackItem(BaseModel):
    id: str
    version: str
    source: Optional[str] = None
    scope: Optional[str] = None
    rules_total: int = 0
    rules_redact: int = 0


class PackList(BaseModel):
    items: List[PackItem]
    total: int


def _as_dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Mapping):
        return dict(obj)
    if obj is None:
        return {}
    return dict(cast(Dict[str, Any], obj))


def _get_policy_module():
    try:
        from app.services import policy as pol

        return pol
    except Exception:
        return None


def _merged_policy(pol) -> Dict[str, Any]:
    try:
        if hasattr(pol, "get_active_policy"):
            return _as_dict(pol.get_active_policy())
        if hasattr(pol, "get"):
            return _as_dict(pol.get())
    except Exception:
        pass
    return {}


def _hash_short(obj: Any) -> str:
    try:
        data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:12]
    except Exception:
        return "unknown"


def _count_rules(policy: Dict[str, Any]) -> Dict[str, int]:
    rules = _as_dict(policy.get("rules"))
    redact_value = rules.get("redact")
    red_ct = 0
    try:
        if isinstance(redact_value, (list, tuple, set, frozenset)):
            red_ct = len(redact_value)
        elif isinstance(redact_value, dict):
            red_ct = len(redact_value)
        elif isinstance(redact_value, (int, float)):
            red_ct = int(redact_value)
        elif isinstance(redact_value, str):
            red_ct = int(redact_value)
        elif redact_value is not None:
            red_ct = int(str(redact_value))
    except Exception:
        red_ct = 0
    total = 0
    for value in rules.values():
        try:
            total += len(value) if hasattr(value, "__len__") else 0
        except Exception:
            pass
    return {"total": int(total), "redact": int(red_ct)}


def _list_packs() -> List[PackItem]:
    pol = _get_policy_module()
    items: List[PackItem] = []
    if not pol:
        return items

    for fn_name in ("list_packs", "get_packs", "active_packs"):
        fn = getattr(pol, fn_name, None)
        if callable(fn):
            try:
                packs = fn()
                for pack in packs or []:
                    data = _as_dict(pack)
                    pack_id = str(
                        data.get("id")
                        or data.get("name")
                        or data.get("key")
                        or f"pack-{len(items) + 1}"
                    )
                    version = str(
                        data.get("version") or data.get("hash") or data.get("etag") or "unknown"
                    )
                    source = data.get("source") or data.get("path") or data.get("repo")
                    scope = data.get("scope")
                    policy = _as_dict(data.get("policy"))
                    counts = _count_rules(policy) if policy else {"total": 0, "redact": 0}
                    items.append(
                        PackItem(
                            id=pack_id,
                            version=version,
                            source=source,
                            scope=scope,
                            rules_total=counts["total"],
                            rules_redact=counts["redact"],
                        )
                    )
                return items
            except Exception:
                break

    merged = _merged_policy(pol)
    packs_meta = merged.get("packs") or merged.get("@packs") or []
    for meta in packs_meta or []:
        data = _as_dict(meta)
        pack_id = str(data.get("id") or data.get("name") or f"pack-{len(items) + 1}")
        version = str(data.get("version") or data.get("hash") or "unknown")
        source = data.get("source") or data.get("path")
        scope = data.get("scope")
        subtree = _as_dict(merged.get(pack_id))
        counts = _count_rules(subtree) if subtree else {"total": 0, "redact": 0}
        items.append(
            PackItem(
                id=pack_id,
                version=version,
                source=source,
                scope=scope,
                rules_total=counts["total"],
                rules_redact=counts["redact"],
            )
        )
    if items:
        return items

    counts = _count_rules(merged)
    version = "unknown"
    try:
        if hasattr(pol, "current_rules_version"):
            version = str(pol.current_rules_version() or "unknown")
        elif merged:
            version = _hash_short(merged)
    except Exception:
        if merged:
            version = _hash_short(merged)
    if merged:
        items.append(
            PackItem(
                id="merged",
                version=version,
                source=None,
                scope="global",
                rules_total=counts["total"],
                rules_redact=counts["redact"],
            )
        )
    return items


@router.get("/admin/api/policy/packs", response_model=PackList)
async def api_packs(request: Request):
    items = _list_packs()
    return JSONResponse(PackList(items=items, total=len(items)).model_dump())


@router.get("/admin/policy/packs", response_class=HTMLResponse)
async def ui_packs(
    request: Request,
    q: Optional[str] = Query(None, description="Search id/source"),
):
    items = _list_packs()
    needle = (q or "").strip().lower()
    if needle:
        items = [
            item
            for item in items
            if needle in item.id.lower()
            or (item.source and needle in item.source.lower())
        ]
    return templates.TemplateResponse(
        request,
        "policy_packs.html",
        {"items": items, "q": q or "", "total": len(items)},
    )
