from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable, Mapping

try:
    # Present in this codebase; caller wiring decides when to use it.
    from app.services.audit_forwarder import emit_audit_event
except Exception:  # pragma: no cover
    emit_audit_event = None  # type: ignore[assignment]


def record_bindings_audit_event(kind: str, payload: Mapping[str, Any]) -> None:
    """
    Wrapper to forward an audit event. If the forwarder is unavailable,
    safely do nothing. Keeps tests decoupled from audit infra.
    """
    if emit_audit_event is None:  # pragma: no cover
        return
    try:
        event: dict[str, Any] = {"kind": kind, **dict(payload)}
        emit_audit_event(event)
    except Exception:
        # Never raise from audit path; this is best-effort logging.
        pass


def record_validation_results(issues: Iterable[object]) -> None:
    """
    Convenience: serialize validation issues and forward once.
    """
    items: list[Any] = []
    for it in issues:
        try:
            items.append(asdict(it))  # type: ignore[call-overload]
        except Exception:
            items.append(repr(it))
    record_bindings_audit_event("bindings.validation", {"issues": items})

