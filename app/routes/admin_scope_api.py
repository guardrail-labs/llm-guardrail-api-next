from __future__ import annotations

import importlib
from typing import Any, Dict, Iterable, List, TypedDict, Union, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.middleware.scope import require_effective_scope, set_effective_scope_headers
from app.security.rbac import require_admin  # authenticated admin user/session

router = APIRouter(prefix="/admin/api/scope", tags=["admin"])


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


# ------------------------- Adapters (read-only) -------------------------


def _coerce_scope_value(value: Union[str, Iterable[str]]) -> Union[str, List[str]]:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [str(item) for item in value]
    try:
        return [str(item) for item in list(value)]
    except TypeError:
        return str(value)


def _get_policy_packs(tenant: str, bot: str) -> List[PolicyPackInfo]:
    try:
        scope_read = importlib.import_module("app.services.scope_read")
    except Exception:
        scope_read = None
    if scope_read is not None:
        getter = getattr(scope_read, "get_policy_packs", None)
        if callable(getter):
            try:
                packs = getter(tenant, bot)
                return cast(List[PolicyPackInfo], packs)
            except Exception:
                pass

    try:
        from app.services.admin_config import get_policy_packs_for

        packs = get_policy_packs_for(tenant, bot) or []
        out: List[PolicyPackInfo] = []
        for p in packs:
            if isinstance(p, dict):
                name = str(p.get("name", ""))
                source = str(p.get("source", "local"))
                version = str(p.get("version", ""))
            else:
                name = str(getattr(p, "name", ""))
                source = str(getattr(p, "source", "local"))
                version = str(getattr(p, "version", ""))
            out.append({"name": name, "source": source, "version": version})
        return out
    except Exception:
        return []


def _get_mitigation_overrides(tenant: str, bot: str) -> Dict[str, MitigationOverrideInfo]:
    try:
        scope_read = importlib.import_module("app.services.scope_read")
    except Exception:
        scope_read = None
    if scope_read is not None:
        getter = getattr(scope_read, "get_mitigation_overrides", None)
        if callable(getter):
            try:
                overrides = getter(tenant, bot)
                return cast(Dict[str, MitigationOverrideInfo], overrides)
            except Exception:
                pass

    try:
        from app.services.mitigations import list_overrides_for

        overrides = list_overrides_for(tenant, bot) or {}
        out: Dict[str, MitigationOverrideInfo] = {}
        for rule, meta in overrides.items():
            if isinstance(meta, dict):
                enabled = bool(meta.get("enabled", False))
                lm = int(meta.get("last_modified", 0))
            else:
                enabled = bool(getattr(meta, "enabled", False))
                lm = int(getattr(meta, "last_modified", 0))
            out[str(rule)] = {"enabled": enabled, "last_modified": lm}
        return out
    except Exception:
        return {}


def _get_secret_set_names(tenant: str, bot: str) -> List[str]:
    try:
        scope_read = importlib.import_module("app.services.scope_read")
    except Exception:
        scope_read = None
    if scope_read is not None:
        getter = getattr(scope_read, "get_secret_set_names", None)
        if callable(getter):
            try:
                names = getter(tenant, bot)
                return [str(name) for name in list(cast(Iterable[Any], names))]
            except Exception:
                pass

    try:
        from app.services.secrets import list_secret_set_names

        names = list_secret_set_names(tenant, bot) or []
        return [str(n) for n in names]
    except Exception:
        return []


# ------------------------- Endpoints -------------------------


@router.get("/effective", response_model=EffectiveScope)
def get_effective_scope(
    response: Response,
    current_user=Depends(require_admin),
) -> EffectiveScope:
    """
    Returns the caller's effective scope as JSON and sets X-Effective-* headers.
    """
    eff_tenant, eff_bot = require_effective_scope(
        user=current_user,
        metric_endpoint="admin_scope_effective",
    )
    set_effective_scope_headers(response, eff_tenant, eff_bot)

    out: EffectiveScope = {}
    if eff_tenant is not None:
        out["effective_tenant"] = _coerce_scope_value(eff_tenant)
    if eff_bot is not None:
        out["effective_bot"] = _coerce_scope_value(eff_bot)
    return out


@router.get("/bindings", response_model=BindingsResponse)
def get_bindings(
    response: Response,
    tenant: str = Query(..., description="Tenant id (required)"),
    bot: str = Query(..., description="Bot id (required)"),
    current_user=Depends(require_admin),
) -> BindingsResponse:
    """
    Read-only: policy pack bindings and mitigation overrides for a specific tenant/bot.
    """
    eff_tenant, eff_bot = require_effective_scope(
        user=current_user,
        tenant=tenant,
        bot=bot,
        metric_endpoint="admin_scope_bindings",
    )
    # Multi-scope token must resolve to a single scope when filters are provided.
    if isinstance(eff_tenant, list) or isinstance(eff_bot, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )

    set_effective_scope_headers(response, eff_tenant, eff_bot)

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
    current_user=Depends(require_admin),
) -> SecretsResponse:
    """
    Read-only: list **names** of secret sets available to tenant/bot (no values).
    """
    eff_tenant, eff_bot = require_effective_scope(
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

    set_effective_scope_headers(response, eff_tenant, eff_bot)

    names = _get_secret_set_names(tenant, bot)
    return {"secret_sets": names}
