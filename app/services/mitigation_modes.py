"""In-memory storage for mitigation modes per tenant/bot."""
from __future__ import annotations

from threading import RLock
from typing import Dict, Mapping, Tuple

DEFAULT_MODES: Dict[str, bool] = {
    "block": False,
    "redact": False,
    "clarify_first": False,
}

_STORE: Dict[Tuple[str, str], Dict[str, bool]] = {}
_LOCK = RLock()


def _normalize_key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "").strip(), (bot or "").strip()


def _clone_modes(modes: Mapping[str, bool]) -> Dict[str, bool]:
    sanitized: Dict[str, bool] = {}
    for flag, default in DEFAULT_MODES.items():
        sanitized[flag] = True if modes.get(flag) is True else default
    return sanitized


def get_modes(tenant: str, bot: str) -> Dict[str, bool]:
    """Return mitigation modes for the tenant/bot pair (defaults if unset)."""
    key = _normalize_key(tenant, bot)
    with _LOCK:
        stored = _STORE.get(key)
        if stored is None:
            return dict(DEFAULT_MODES)
        return dict(stored)


def set_modes(tenant: str, bot: str, modes: Mapping[str, bool]) -> Dict[str, bool]:
    """Persist mitigation modes for the tenant/bot pair and return the saved copy."""
    key = _normalize_key(tenant, bot)
    sanitized = _clone_modes(modes)
    with _LOCK:
        _STORE[key] = sanitized
    return dict(sanitized)


def delete_modes(tenant: str, bot: str) -> None:
    """Remove mitigation modes for the tenant/bot pair (no-op if absent)."""
    key = _normalize_key(tenant, bot)
    with _LOCK:
        _STORE.pop(key, None)


def _reset_for_tests() -> None:
    """Test helper to wipe all stored mitigation modes."""
    with _LOCK:
        _STORE.clear()
