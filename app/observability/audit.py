"""Lightweight helpers for observability-related audit events."""

from __future__ import annotations

from typing import Any, Dict

try:  # pragma: no cover - audit forwarding is optional in some builds
    from app.services.audit import emit_audit_event as _emit_audit_event
except Exception:  # pragma: no cover - gracefully degrade when unavailable
    _emit_audit_event = None  # type: ignore[assignment]


def record_scope_autoconstraint_audit(*, tenant: str, bot: str, multi: bool, endpoint: str) -> None:
    """Emit an audit event describing an auto-constrained scope decision."""

    if _emit_audit_event is None:
        return

    payload: Dict[str, Any] = {
        "action": "scope.autoconstraint",
        "tenant_id": tenant,
        "bot_id": bot,
        "direction": "admin_ui",
        "meta": {
            "multi_scope": bool(multi),
            "endpoint": endpoint or "unknown",
        },
    }

    try:
        _emit_audit_event(payload)
    except Exception:  # pragma: no cover - audit is best-effort
        pass
