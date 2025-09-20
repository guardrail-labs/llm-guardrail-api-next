"""Lightweight in-memory storage for mitigation mode overrides."""

from __future__ import annotations

from typing import Literal, Optional, Tuple

Mode = Literal["block", "clarify", "redact"]
_VALID = {"block", "clarify", "redact"}


def validate_mode(mode: str) -> Mode:
    """Validate and normalise a mitigation mode string."""

    if mode not in _VALID:
        raise ValueError(f"invalid mitigation mode: {mode}")
    return mode  # type: ignore[return-value]


def _key(tenant: str, bot: str) -> str:
    tenant_id = tenant or "default"
    bot_id = bot or "default"
    return f"mitigation:{tenant_id}:{bot_id}"


# NOTE: Replace with Redis/KV in production deployments. The tests patch this.
_STORE: dict[str, str] = {}


def get_mode(tenant: str, bot: str) -> Optional[Mode]:
    raw = _STORE.get(_key(tenant, bot))
    if not raw:
        return None
    return validate_mode(raw)


def set_mode(tenant: str, bot: str, mode: Mode) -> None:
    _STORE[_key(tenant, bot)] = validate_mode(mode)


def clear_mode(tenant: str, bot: str) -> None:
    _STORE.pop(_key(tenant, bot), None)


def resolve_mode(*, tenant: str, bot: str, policy_default: Mode) -> Tuple[Mode, str]:
    """Return the active mitigation mode and the source of that value."""

    explicit = get_mode(tenant, bot)
    if explicit:
        return explicit, "explicit"
    return policy_default, "default"


def _reset_for_tests() -> None:
    _STORE.clear()
