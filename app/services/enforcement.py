from __future__ import annotations

import os
from typing import Any, Literal, Mapping

Mode = Literal["allow", "execute_locked", "deny"]


def _truthy_env(name: str, default: str) -> bool:
    raw = os.getenv(name, default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _lock_enabled() -> bool:
    return _truthy_env("LOCK_ENABLE", "true")


def _lock_deny_as_execute() -> bool:
    return _truthy_env("LOCK_DENY_AS_EXECUTE", "true")


def choose_mode(policy_result: Mapping[str, Any] | None, family: str) -> Mode:
    family_norm = str(family or "").strip().lower()
    default_mode: Mode = "allow" if family_norm == "allow" else "deny"

    if not _lock_enabled():
        return default_mode

    action_value: str | None = None
    if policy_result is not None:
        action_raw = policy_result.get("action")
        if isinstance(action_raw, str):
            action_value = action_raw.strip().lower()
            if action_value == "allow":
                return "allow"
            if action_value == "lock":
                return "execute_locked"
            if action_value == "deny":
                return "execute_locked" if _lock_deny_as_execute() else "deny"

    if default_mode == "deny" and _lock_deny_as_execute():
        if action_value in (None, "", "deny"):
            return "execute_locked"

    return default_mode
