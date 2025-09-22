from __future__ import annotations

from collections.abc import Iterable
from typing import Dict, List, Optional, TypedDict, Union

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.middleware.scope import require_effective_scope, set_effective_scope_headers

router = APIRouter(prefix="/admin/api/scope", tags=["admin"])


class PolicyPackInfo(TypedDict):
    name: str
    source: str
    version: str


class MitigationOverrideInfo(TypedDict):
    enabled: bool
    last_modified: int


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


ScopeValue = Optional[Union[str, Iterable[str]]]


def _normalize_scope_value(value: ScopeValue) -> Optional[Union[str, List[str]]]:
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        return str(value)
    try:
        return [str(item) for item in value]
    except TypeError:
        return str(value)


# ---- Thin service layer wrappers (read-only) ----
# Implemented defensively to avoid hard-coupling; return empty lists when providers are missing.
def _get_policy_packs(tenant: str, bot: str) -> List[PolicyPackInfo]:
    try:
        from app.services.scope_read import get_policy_packs

        return get_policy_packs(tenant, bot)
    except Exception:
        pass
    try:
        from app.services.admin_config import get_policy_packs_for

        packs = get_policy_packs_for(tenant, bot)
        out: List[PolicyPackInfo] = []
        for pack in packs or []:
            name = str(getattr(pack, "name", getattr(pack, "id", "")))
            if not name and isinstance(pack, dict):
                name = str(pack.get("name", pack.get("id", "")))
            source = str(getattr(pack, "source", ""))
            if not source and isinstance(pack, dict):
                source = str(pack.get("source", "local"))
            version = str(getattr(pack, "version", ""))
            if not version and isinstance(pack, dict):
                version = str(pack.get("version", ""))
            out.append({
                "name": name,
                "source": source or "local",
                "version": version,
            })
        return out
    except Exception:
        return []


def _get_mitigation_overrides(tenant: str, bot: str) -> Dict[str, MitigationOverrideInfo]:
    try:
        from app.services.scope_read import get_mitigation_overrides

        return get_mitigation_overrides(tenant, bot)
    except Exception:
        pass
    try:
        from app.services.mitigations import list_overrides_for

        overrides = list_overrides_for(tenant, bot) or {}
        out: Dict[str, MitigationOverrideInfo] = {}
        for rule, meta in overrides.items():
            enabled: bool
            last_modified: int
            if isinstance(meta, dict):
                enabled = bool(meta.get("enabled"))
                raw_last_modified = meta.get("last_modified", 0)
            else:
                enabled = bool(getattr(meta, "enabled", False))
                raw_last_modified = getattr(meta, "last_modified", 0)
            try:
                last_modified = int(raw_last_modified)
            except Exception:
                last_modified = 0
            out[str(rule)] = {"enabled": enabled, "last_modified": last_modified}
        return out
    except Exception:
        return {}


def _get_secret_set_names(tenant: str, bot: str) -> List[str]:
    try:
        from app.services.scope_read import get_secret_set_names

        return get_secret_set_names(tenant, bot)
    except Exception:
        pass
    try:
        from app.services.secrets import list_secret_set_names

        names = list_secret_set_names(tenant, bot) or []
        return [str(name) for name in names]
    except Exception:
        return []


@router.get("/effective", response_model=EffectiveScope)
def get_effective_scope(response: Response) -> EffectiveScope:
    """Return the caller's effective tenant/bot scope."""

    eff_tenant, eff_bot = require_effective_scope(metric_endpoint="admin_scope_effective")
    set_effective_scope_headers(response, eff_tenant, eff_bot)
    result: EffectiveScope = {}
    tenant_value = _normalize_scope_value(eff_tenant)
    if tenant_value is not None:
        result["effective_tenant"] = tenant_value
    bot_value = _normalize_scope_value(eff_bot)
    if bot_value is not None:
        result["effective_bot"] = bot_value
    return result


@router.get("/bindings", response_model=BindingsResponse)
def get_bindings(
    response: Response,
    tenant: str = Query(..., description="Tenant id (required)"),
    bot: str = Query(..., description="Bot id (required)"),
) -> BindingsResponse:
    """Read-only policy pack bindings and mitigation overrides for a tenant/bot."""

    eff_tenant, eff_bot = require_effective_scope(
        tenant=tenant,
        bot=bot,
        metric_endpoint="admin_scope_bindings",
    )
    if eff_tenant is not None and not isinstance(eff_tenant, (str, bytes)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )
    if eff_bot is not None and not isinstance(eff_bot, (str, bytes)):
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
) -> SecretsResponse:
    """Read-only list of secret set names available to a tenant/bot."""

    eff_tenant, eff_bot = require_effective_scope(
        tenant=tenant,
        bot=bot,
        metric_endpoint="admin_scope_secrets",
    )
    if eff_tenant is not None and not isinstance(eff_tenant, (str, bytes)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )
    if eff_bot is not None and not isinstance(eff_bot, (str, bytes)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-scope token requires explicit single tenant and bot.",
        )
    set_effective_scope_headers(response, eff_tenant, eff_bot)

    names = _get_secret_set_names(tenant, bot)
    return {"secret_sets": names}
