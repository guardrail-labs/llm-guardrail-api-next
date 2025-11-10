"""Scope utilities for admin middleware and dependencies."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Callable, Dict, Optional, Tuple, Union, cast

from fastapi import Depends, HTTPException, Query, Response

from app.observability.metrics import inc_scope_autoconstraint
from app.security.rbac import (
    RBACError,
    coerce_query_to_scope,
    ensure_scope,
    require_viewer,
)
from app.services import config

RecordScopeAuditFn = Callable[..., None]

_scope_audit: Optional[RecordScopeAuditFn]
try:  # pragma: no cover - optional audit helper may not be present
    from app.observability.audit import record_scope_autoconstraint_audit
except Exception:  # pragma: no cover - guard against import errors
    _scope_audit = None
else:
    _scope_audit = cast(RecordScopeAuditFn, record_scope_autoconstraint_audit)

Effective = Tuple[
    Optional[Union[str, Iterable[str]]],
    Optional[Union[str, Iterable[str]]],
]


def require_effective_scope(
    user: Dict[str, Any] = Depends(require_viewer),
    tenant: Optional[str] = Query(None),
    bot: Optional[str] = Query(None),
    *,
    metric_endpoint: str = "unknown",
) -> Effective:
    """Return the effective tenant/bot scope for the current user."""

    scope = (user.get("scope") if isinstance(user, dict) else getattr(user, "scope", None)) or {}
    tenant_scope = scope.get("tenants", "*") if isinstance(scope, dict) else "*"
    bot_scope = scope.get("bots", "*") if isinstance(scope, dict) else "*"

    endpoint_label = metric_endpoint or "unknown"

    def _explicit_query(value: Optional[str]) -> bool:
        return value not in (None, "")

    if not config.SCOPE_AUTOCONSTRAIN_ENABLED:
        try:
            ensure_scope(user, tenant=tenant, bot=bot)
        except RBACError as exc:  # pragma: no cover - safety
            inc_scope_autoconstraint(
                mode="off",
                result="missing",
                multi=False,
                endpoint=endpoint_label,
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        inc_scope_autoconstraint(
            mode="off",
            result="explicit",
            multi=False,
            endpoint=endpoint_label,
        )
        return tenant, bot

    try:
        eff_tenant = coerce_query_to_scope(tenant_scope, tenant)
        eff_bot = coerce_query_to_scope(bot_scope, bot)
    except RBACError as exc:
        inc_scope_autoconstraint(
            mode="on",
            result="conflict",
            multi=False,
            endpoint=endpoint_label,
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    multi_scope = _is_multi_scope_value(eff_tenant) or _is_multi_scope_value(eff_bot)
    was_explicit = _explicit_query(tenant) or _explicit_query(bot)

    inc_scope_autoconstraint(
        mode="on",
        result="explicit" if was_explicit else "constrained",
        multi=multi_scope,
        endpoint=endpoint_label,
    )

    if not was_explicit and _scope_audit:
        try:
            _scope_audit(
                tenant=_fmt_scope_val(eff_tenant),
                bot=_fmt_scope_val(eff_bot),
                multi=multi_scope,
                endpoint=endpoint_label,
            )
        except Exception:  # pragma: no cover - audit is best-effort
            pass

    return eff_tenant, eff_bot


def _fmt_scope_val(value: Optional[Union[str, Iterable[str]]]) -> str:
    if value is None:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def _is_multi_scope_value(value: Optional[Union[str, Iterable[str]]]) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value) > 1
    try:
        length = len(value)  # type: ignore[arg-type]
    except TypeError:
        return False
    return length > 1


def set_effective_scope_headers(
    response: Response,
    tenant: Optional[Union[str, Iterable[str]]],
    bot: Optional[Union[str, Iterable[str]]],
) -> None:
    response.headers["X-Guardrail-Scope-Tenant"] = _fmt_scope_val(tenant)
    response.headers["X-Guardrail-Scope-Bot"] = _fmt_scope_val(bot)


def as_iterable_scope(value: Optional[Union[str, Iterable[str]]]) -> Optional[Iterable[str]]:
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
        detail=(f"multiple {field} scopes; specify ?{field}= or use a bulk export strategy"),
    )
