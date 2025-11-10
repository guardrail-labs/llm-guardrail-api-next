from __future__ import annotations

import importlib
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from typing_extensions import TypedDict  # pydantic v2 + py<3.12

router = APIRouter(prefix="/admin/api/scope", tags=["admin"])

# Lazy imports to avoid mypy attr-defined on optional modules
_rbac: Any = importlib.import_module("app.security.rbac")
_admin_session: Any = importlib.import_module("app.middleware.admin_session")


# ------------------------- Typed payloads -------------------------


class PolicyPackInfo(TypedDict):
    name: str
    source: str  # "golden" | "local" | "remote"
    version: str


class MitigationOverrideInfo(TypedDict):
    enabled: bool
    last_modified: int  # unix seconds


class EffectiveScope(TypedDict, total=False):
    effective_tenant: Union[str, List[str]]
    effective_bot: Union[str, List[str]]


class BindingsResponse(TypedDict):
    tenant: str
    bot: str
    policy_packs: List[PolicyPackInfo]
    mitigation_overrides: Dict[str, MitigationOverrideInfo]


class SecretsResponse(TypedDict):
    secret_sets: List[str]


# ------------------------- Dependency wrappers -------------------------


def _require_admin_dep(request: Request) -> Any:
    """Wrapper around middleware-admin require_admin."""
    return _admin_session.require_admin(request)


# ------------------------- Import helpers -------------------------


def _try_import(module: str) -> Optional[Any]:
    try:
        return importlib.import_module(module)
    except Exception:
        return None


# ------------------------- Provider adapters -------------------------


def _coerce_pack(obj: Any) -> PolicyPackInfo:
    if isinstance(obj, dict):
        name = str(obj.get("name", ""))
        source = str(obj.get("source", "local"))
        version = str(obj.get("version", ""))
        return {"name": name, "source": source, "version": version}
    return {
        "name": str(getattr(obj, "name", "")),
        "source": str(getattr(obj, "source", "local")),
        "version": str(getattr(obj, "version", "")),
    }


def _get_policy_packs(tenant: str, bot: str) -> List[PolicyPackInfo]:
    # 1) scope_read plugin, if present
    scope_read = _try_import("app.services.scope_read")
    if scope_read and hasattr(scope_read, "get_policy_packs"):
        packs_sr: Any = scope_read.get_policy_packs(tenant, bot)
        return [_coerce_pack(p) for p in (packs_sr or [])]

    # 2) other likely providers in this repo (update list as needed)
    candidates: List[Tuple[str, str]] = [
        ("app.services.policy_packs", "get_policy_packs_for"),
        ("app.store.policy_packs", "get_policy_packs_for"),
        ("app.services.bindings", "get_policy_packs_for"),
    ]
    for mod_name, fn in candidates:
        mod = _try_import(mod_name)
        if mod and hasattr(mod, fn):
            func = cast(Any, getattr(mod, fn))
            packs_mod: Any = func(tenant, bot)
            return [_coerce_pack(p) for p in (packs_mod or [])]

    # No provider found
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=("No policy pack provider configured (enable scope_read or policy_packs service)."),
    )


def _coerce_override(_rule: str, meta: Any) -> MitigationOverrideInfo:
    if isinstance(meta, dict):
        return {
            "enabled": bool(meta.get("enabled", False)),
            "last_modified": int(meta.get("last_modified", 0)),
        }
    return {
        "enabled": bool(getattr(meta, "enabled", False)),
        "last_modified": int(getattr(meta, "last_modified", 0)),
    }


def _dict_of_overrides(obj: Any) -> Dict[str, MitigationOverrideInfo]:
    out: Dict[str, MitigationOverrideInfo] = {}
    for k, v in (obj or {}).items():
        out[str(k)] = _coerce_override(str(k), v)
    return out


def _get_mitigation_overrides(
    tenant: str,
    bot: str,
) -> Dict[str, MitigationOverrideInfo]:
    # 1) scope_read plugin
    scope_read = _try_import("app.services.scope_read")
    if scope_read and hasattr(scope_read, "get_mitigation_overrides"):
        overrides_sr: Any = scope_read.get_mitigation_overrides(tenant, bot)
        return _dict_of_overrides(overrides_sr)

    # 2) likely providers
    candidates: List[Tuple[str, str]] = [
        ("app.services.mitigations", "list_overrides_for"),
        ("app.store.mitigations", "list_overrides_for"),
    ]
    for mod_name, fn in candidates:
        mod = _try_import(mod_name)
        if mod and hasattr(mod, fn):
            func = cast(Any, getattr(mod, fn))
            overrides_mod: Any = func(tenant, bot)
            return _dict_of_overrides(overrides_mod)

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "No mitigation overrides provider configured "
            "(enable scope_read or mitigations service)."
        ),
    )


def _get_secret_set_names(tenant: str, bot: str) -> List[str]:
    # 1) scope_read plugin
    scope_read = _try_import("app.services.scope_read")
    if scope_read and hasattr(scope_read, "get_secret_set_names"):
        names_sr: Any = scope_read.get_secret_set_names(tenant, bot)
        return [str(n) for n in (names_sr or [])]

    # 2) likely providers
    candidates: List[Tuple[str, str]] = [
        ("app.services.secrets", "list_secret_set_names"),
        ("app.store.secrets", "list_secret_set_names"),
    ]
    for mod_name, fn in candidates:
        mod = _try_import(mod_name)
        if mod and hasattr(mod, fn):
            func = cast(Any, getattr(mod, fn))
            names_mod: Any = func(tenant, bot)
            return [str(n) for n in (names_mod or [])]

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=("No secrets provider configured (enable scope_read or secrets service)."),
    )


# ------------------------- Endpoints -------------------------


@router.get("/effective", response_model=EffectiveScope)
def get_effective_scope(
    response: Response,
    current_user: Any = Depends(_require_admin_dep),
) -> EffectiveScope:
    """
    Returns the caller's effective scope as JSON and sets X-Effective-* headers.
    """
    eff_tenant, eff_bot = _rbac.require_effective_scope(
        user=current_user,
        metric_endpoint="admin_scope_effective",
    )
    _rbac.set_effective_scope_headers(response, eff_tenant, eff_bot)

    out: EffectiveScope = {}
    if eff_tenant is not None:
        out["effective_tenant"] = eff_tenant
    if eff_bot is not None:
        out["effective_bot"] = eff_bot
    return out


@router.get("/bindings", response_model=BindingsResponse)
def get_bindings(
    response: Response,
    tenant: str = Query(..., description="Tenant id (required)"),
    bot: str = Query(..., description="Bot id (required)"),
    current_user: Any = Depends(_require_admin_dep),
) -> BindingsResponse:
    """
    Read-only: policy pack bindings and mitigation overrides for a specific
    tenant/bot.
    """
    eff_tenant, eff_bot = _rbac.require_effective_scope(
        user=current_user,
        tenant=tenant,
        bot=bot,
        metric_endpoint="admin_scope_bindings",
    )
    # If multi-scope resolves to a list, the request must be narrowed.
    if isinstance(eff_tenant, list) or isinstance(eff_bot, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )

    _rbac.set_effective_scope_headers(response, eff_tenant, eff_bot)

    packs = _get_policy_packs(tenant, bot)
    overrides = _get_mitigation_overrides(tenant, bot)
    return {
        "tenant": tenant,
        "bot": bot,
        "policy_packs": packs,
        "mitigation_overrides": overrides,
    }


@router.get("/secrets", response_model=SecretsResponse)
def get_secret_sets(
    response: Response,
    tenant: str = Query(..., description="Tenant id (required)"),
    bot: str = Query(..., description="Bot id (required)"),
    current_user: Any = Depends(_require_admin_dep),
) -> SecretsResponse:
    """
    Read-only: list **names** of secret sets available to tenant/bot (no values).
    """
    eff_tenant, eff_bot = _rbac.require_effective_scope(
        user=current_user,
        tenant=tenant,
        bot=bot,
        metric_endpoint="admin_scope_secrets",
    )
    if isinstance(eff_tenant, list) or isinstance(eff_bot, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )

    _rbac.set_effective_scope_headers(response, eff_tenant, eff_bot)

    names = _get_secret_set_names(tenant, bot)
    return {"secret_sets": names}
