"""Scope utilities for admin middleware and dependencies."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Dict, Optional, Tuple, Union

from fastapi import Depends, HTTPException, Query, Response

from app.security.rbac import (
    RBACError,
    coerce_query_to_scope,
    ensure_scope,
    require_viewer,
)
from app.services import config

Effective = Tuple[
    Optional[Union[str, Iterable[str]]],
    Optional[Union[str, Iterable[str]]],
]


def require_effective_scope(
    user: Dict[str, Any] = Depends(require_viewer),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
) -> Effective:
    """Return the effective tenant/bot scope for the current user."""

    scope = (
        user.get("scope")
        if isinstance(user, dict)
        else getattr(user, "scope", None)
    ) or {}
    tenant_scope = scope.get("tenants", "*") if isinstance(scope, dict) else "*"
    bot_scope = scope.get("bots", "*") if isinstance(scope, dict) else "*"

    if not config.SCOPE_AUTOCONSTRAIN_ENABLED:
        try:
            ensure_scope(user, tenant=tenant, bot=bot)
        except RBACError as exc:  # pragma: no cover - safety
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return tenant, bot

    try:
        eff_tenant = coerce_query_to_scope(tenant_scope, tenant)
        eff_bot = coerce_query_to_scope(bot_scope, bot)
    except RBACError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return eff_tenant, eff_bot


def _fmt_scope_val(value: Optional[Union[str, Iterable[str]]]) -> str:
    if value is None:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def set_effective_scope_headers(
    response: Response,
    tenant: Optional[Union[str, Iterable[str]]],
    bot: Optional[Union[str, Iterable[str]]],
) -> None:
    response.headers["X-Guardrail-Scope-Tenant"] = _fmt_scope_val(tenant)
    response.headers["X-Guardrail-Scope-Bot"] = _fmt_scope_val(bot)


def as_iterable_scope(
    value: Optional[Union[str, Iterable[str]]]
) -> Optional[Iterable[str]]:
    """Normalize a scope value to an iterable of strings or ``None``."""

    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    return value


def as_single_scope(
    value: Optional[Union[str, Iterable[str]]],
    *,
    field: str,
) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    items = list(value)
    if not items:
        return None
    if len(items) == 1:
        return str(items[0])
    raise HTTPException(
        status_code=400,
        detail=(
            f"multiple {field} scopes; specify ?{field}= or use a bulk export strategy"
        ),
    )

