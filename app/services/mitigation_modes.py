"""In-memory storage for mitigation modes per tenant/bot."""

from __future__ import annotations

from threading import RLock
from typing import Dict, Mapping, Tuple

from app.services import mitigation_prefs as prefs

DEFAULT_MODES: Dict[str, bool] = {
    "block": False,
    "redact": False,
    "clarify_first": False,
}

_LOCK = RLock()
_LEGACY_STORE: Dict[Tuple[str, str], Dict[str, bool]] = {}


def _normalize_key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "").strip(), (bot or "").strip()


def _clone_modes(modes: Mapping[str, bool]) -> Dict[str, bool]:
    sanitized: Dict[str, bool] = {}
    for flag, default in DEFAULT_MODES.items():
        sanitized[flag] = True if modes.get(flag) is True else default
    return sanitized


def _from_mode(mode: prefs.Mode | None) -> Dict[str, bool]:
    values = dict(DEFAULT_MODES)
    if mode == "block":
        values["block"] = True
    elif mode == "redact":
        values["redact"] = True
    elif mode == "clarify":
        values["clarify_first"] = True
    return values


def get_modes(tenant: str, bot: str) -> Dict[str, bool]:
    """Return mitigation modes for the tenant/bot pair (defaults if unset)."""

    key = _normalize_key(tenant, bot)
    with _LOCK:
        stored = _LEGACY_STORE.get(key)
        if stored is not None:
            return dict(stored)
        mode = prefs.get_mode(*key)
        return _from_mode(mode)


def set_modes(tenant: str, bot: str, modes: Mapping[str, bool]) -> Dict[str, bool]:
    """Persist mitigation modes for the tenant/bot pair and return the saved copy."""

    key = _normalize_key(tenant, bot)
    sanitized = _clone_modes(modes)
    selected: prefs.Mode | None = None
    if sanitized.get("block"):
        selected = "block"
    elif sanitized.get("redact"):
        selected = "redact"
    elif sanitized.get("clarify_first"):
        selected = "clarify"

    with _LOCK:
        _LEGACY_STORE[key] = dict(sanitized)
        if selected:
            prefs.set_mode(*key, selected)
        else:
            prefs.clear_mode(*key)
    return dict(sanitized)


def delete_modes(tenant: str, bot: str) -> None:
    """Remove mitigation modes for the tenant/bot pair (no-op if absent)."""

    key = _normalize_key(tenant, bot)
    with _LOCK:
        _LEGACY_STORE.pop(key, None)
        prefs.clear_mode(*key)


def _reset_for_tests() -> None:
    """Test helper to wipe all stored mitigation modes."""

    with _LOCK:
        _LEGACY_STORE.clear()
        prefs._reset_for_tests()
