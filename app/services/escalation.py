from __future__ import annotations

import time
from typing import Dict, Literal, Tuple

from app.services.config_store import get_config

Mode = Literal["normal", "execute_locked", "full_quarantine"]

_STATE: Dict[str, Tuple[float, int, float]] = {}


def _cfg() -> Tuple[bool, int, int, int]:
    data = get_config()
    enabled = bool(data.get("escalation_enabled", False))
    deny_threshold = max(1, int(data.get("escalation_deny_threshold", 3)))
    window_secs = max(1, int(data.get("escalation_window_secs", 300)))
    cooldown_secs = max(1, int(data.get("escalation_cooldown_secs", 900)))
    return enabled, deny_threshold, window_secs, cooldown_secs


def _enabled() -> bool:
    enabled, _, _, _ = _cfg()
    return enabled


def _deny_threshold() -> int:
    _, threshold, _, _ = _cfg()
    return threshold


def _window_secs() -> int:
    _, _, window, _ = _cfg()
    return window


def _cooldown_secs() -> int:
    _, _, _, cooldown = _cfg()
    return cooldown


def _now() -> float:
    return time.time()


def record_and_decide(fp: str, family: str, *, now: float | None = None) -> Tuple[Mode, int]:
    """Record the latest decision family and return escalation mode and retry."""

    enabled, deny_threshold, window_secs, cooldown_secs = _cfg()

    ts = now if now is not None else _now()

    if not fp:
        return "normal", 0

    entry = _STATE.get(fp)

    if not enabled:
        if entry and ts - entry[0] > window_secs:
            _STATE.pop(fp, None)
        return "normal", 0

    if entry is not None:
        first_ts, count, quarantine_until = entry
        if quarantine_until > ts:
            retry = max(1, int(quarantine_until - ts))
            return "full_quarantine", retry
    else:
        first_ts, count, quarantine_until = ts, 0, 0.0

    if family == "deny":
        if ts - first_ts > window_secs:
            first_ts, count = ts, 0
        count += 1
        if count >= deny_threshold:
            quarantine_until = ts + cooldown_secs
            _STATE[fp] = (first_ts, count, quarantine_until)
            return "full_quarantine", max(1, int(cooldown_secs))
        _STATE[fp] = (first_ts, count, 0.0)
        return "normal", 0

    if entry is None:
        return "normal", 0

    if ts - first_ts > window_secs:
        _STATE.pop(fp, None)
    return "normal", 0


def reset_state() -> None:
    _STATE.clear()


def reset_memory() -> None:  # backward compat for existing tests
    reset_state()


def is_enabled() -> bool:
    enabled, _, _, _ = _cfg()
    return enabled
