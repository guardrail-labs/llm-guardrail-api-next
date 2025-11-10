"""Bindings service helpers."""

from __future__ import annotations

from typing import Any, Dict, List


def list_bindings() -> List[Dict[str, Any]]:
    """Return a simplified list of active bindings.

    Each item contains ``tenant``, ``bot``, and ``policy_version``.  If the
    underlying repository or models are unavailable, an empty list is returned.
    """

    try:
        from app.services.bindings.repository import get_bindings

        items = []
        for b in get_bindings():
            items.append(
                {
                    "tenant": getattr(b, "tenant_id", getattr(b, "tenant", "")),
                    "bot": getattr(b, "bot_id", getattr(b, "bot", "")),
                    "policy_version": getattr(b, "policy_version", ""),
                }
            )
        return items
    except Exception:  # pragma: no cover - optional dependency
        return []


__all__ = ["list_bindings"]
