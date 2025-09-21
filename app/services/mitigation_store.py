from __future__ import annotations

from typing import Dict, List, Optional, Tuple, TypedDict


class Entry(TypedDict):
    tenant: str
    bot: str
    mode: str  # "block" | "clarify" | "redact"


_STORE: Dict[Tuple[str, str], str] = {}


def _key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "").strip(), (bot or "").strip()


def get_mode(tenant: str, bot: str) -> Optional[str]:
    return _STORE.get(_key(tenant, bot))


def set_mode(tenant: str, bot: str, mode: str) -> None:
    if mode not in ("block", "clarify", "redact"):
        raise ValueError("invalid mode")
    _STORE[_key(tenant, bot)] = mode


def clear_mode(tenant: str, bot: str) -> None:
    _STORE.pop(_key(tenant, bot), None)


def list_modes() -> List[Entry]:
    return [
        {"tenant": tenant, "bot": bot, "mode": mode}
        for (tenant, bot), mode in sorted(_STORE.items())
    ]


def reset_for_tests() -> None:
    _STORE.clear()

