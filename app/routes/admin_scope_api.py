from __future__ import annotations

from typing import Dict, List, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from typing_extensions import TypedDict  # <-- Pydantic v2 requires this on Python < 3.12

from app.middleware.admin_session import require_admin  # authenticated admin user/session
from app.security.rbac import (
    require_effective_scope,
    set_effective_scope_headers,
)

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

def _get_policy_packs(tenant: str, bot: str) -> List[PolicyPackInfo]:
    try:
        from app.services.scope_read import get_policy_packs  # type: ignore
        return get_policy_packs(tenant, bot)
    except Exception:
        pass

    try:
        from app.services.admin_config import get_policy_packs_for  # type: ignore
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
        from app.services.scope_read import get_mitigation_overrides  # type: ignore
        return get_mitigation_overrides(tenant, bot)
    except Exception:
        pass

    try:
        from app.services.mitigations import list_overrides_for  # type: ignore
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
        from app.services.scope_read import get_secret_set_names  # type: ignore
        return get_secret_set_names(tenant, bot)
    except Exception:
        pass

    try:
        from app.services.secrets import list_secret_set_names  # type: ignore
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
        out["effective_tenant"] = eff_tenant
    if eff_bot is not None:
        out["effective_bot"] = eff_bot
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
