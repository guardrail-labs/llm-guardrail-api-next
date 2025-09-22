from __future__ import annotations

from typing import Iterable, Optional, Tuple, Union

from fastapi import Depends, HTTPException, Query, Response

from app import config
from app.security.rbac import (
    RBACError,
    coerce_query_to_scope,
    ensure_scope,
    require_viewer,
)

ScopeValue = Optional[Union[str, Iterable[str]]]
EffectiveScope = Tuple[ScopeValue, ScopeValue]


def _extract_scope(user: object) -> dict[str, object]:
    if isinstance(user, dict):
        scope = user.get("scope")
    else:
        scope = getattr(user, "scope", None)
    return scope if isinstance(scope, dict) else {}


def require_effective_scope(
    user=Depends(require_viewer),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
) -> EffectiveScope:
    scopes = _extract_scope(user)
    tenant_scope = scopes.get("tenants", "*")
    bot_scope = scopes.get("bots", "*")

    if not config.SCOPE_AUTOCONSTRAIN_ENABLED:
        try:
            ensure_scope(user, tenant=tenant, bot=bot)
        except RBACError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return tenant, bot

    try:
        eff_tenant = coerce_query_to_scope(tenant_scope, tenant)
        eff_bot = coerce_query_to_scope(bot_scope, bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return eff_tenant, eff_bot


def _fmt_scope_val(value: ScopeValue) -> str:
    if value is None:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def set_effective_scope_headers(
    response: Response, eff_tenant: ScopeValue, eff_bot: ScopeValue
) -> None:
    response.headers["X-Guardrail-Scope-Tenant"] = _fmt_scope_val(eff_tenant)
    response.headers["X-Guardrail-Scope-Bot"] = _fmt_scope_val(eff_bot)
