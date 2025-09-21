"""Lightweight in-memory storage for mitigation mode overrides."""

from __future__ import annotations

from typing import Literal, Optional, Tuple

from app.services import mitigation_store

Mode = Literal["block", "clarify", "redact"]
_VALID = {"block", "clarify", "redact"}


def validate_mode(mode: str) -> Mode:
    """Validate and normalise a mitigation mode string."""

    if mode not in _VALID:
        raise ValueError(f"invalid mitigation mode: {mode}")
    return mode  # type: ignore[return-value]


# expose for backwards compatibility in existing tests
_STORE = mitigation_store._STORE


def get_mode(tenant: str, bot: str) -> Optional[Mode]:
    raw = mitigation_store.get_mode(tenant, bot)
    if raw is None:
        return None
    return validate_mode(raw)


def set_mode(tenant: str, bot: str, mode: Mode) -> None:
    mitigation_store.set_mode(tenant, bot, validate_mode(mode))


def clear_mode(tenant: str, bot: str) -> None:
    mitigation_store.clear_mode(tenant, bot)


def resolve_mode(*, tenant: str, bot: str, policy_default: Mode) -> Tuple[Mode, str]:
    """Return the active mitigation mode and the source of that value."""

    explicit = get_mode(tenant, bot)
    if explicit:
        return explicit, "explicit"
    return policy_default, "default"


def _reset_for_tests() -> None:
    mitigation_store.reset_for_tests()
