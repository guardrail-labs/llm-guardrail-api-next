"""Feature flags for service-layer behavior."""

from __future__ import annotations

import os

__all__ = ["SCOPE_AUTOCONSTRAIN_ENABLED"]


def _to_bool(val: object, default: bool = False) -> bool:
    """Best-effort coercion of environment values to booleans."""

    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


# Feature flag (default OFF): when ON, missing tenant/bot are auto-constrained to token scope
SCOPE_AUTOCONSTRAIN_ENABLED: bool = _to_bool(
    os.getenv("SCOPE_AUTOCONSTRAIN_ENABLED"), False
)

