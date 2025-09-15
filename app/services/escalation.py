from __future__ import annotations

import os
import time
from typing import Dict, Literal, Tuple

Mode = Literal["normal", "execute_locked", "full_quarantine"]

def _enabled() -> bool:
    return os.getenv("ESCALATION_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


def _deny_threshold() -> int:
    try:
        raw = int(os.getenv("ESCALATION_DENY_THRESHOLD", "3"))
    except Exception:
        raw = 3
    return max(1, raw)


def _window_secs() -> int:
    try:
        raw = int(os.getenv("ESCALATION_WINDOW_SECS", "300"))
    except Exception:
        raw = 300
    return max(1, raw)


def _cooldown_secs() -> int:
    try:
        raw = int(os.getenv("ESCALATION_COOLDOWN_SECS", "900"))
    except Exception:
        raw = 900
    return max(1, raw)

_STATE: Dict[str, Tuple[float, int, float]] = {}


def _now() -> float:
    return time.time()


def record_and_decide(fp: str, family: str, *, now: float | None = None) -> Tuple[Mode, int]:
    """Record the latest decision family and return escalation mode and retry."""

    if not _enabled():
        return "normal", 0

    if not fp:
        # Without a fingerprint we cannot reliably track; remain normal.
        return "normal", 0

    ts = now if now is not None else _now()
    entry = _STATE.get(fp)

    if entry is not None:
        first_ts, count, quarantine_until = entry
        # Active quarantine holds priority regardless of incoming family.
        if quarantine_until > ts:
            retry = max(1, int(quarantine_until - ts))
            return "full_quarantine", retry
    else:
        first_ts, count, quarantine_until = ts, 0, 0.0

    if family == "deny":
        window = _window_secs()
        if ts - first_ts > window:
            first_ts, count = ts, 0
        count += 1
        threshold = _deny_threshold()
        if count >= threshold:
            cooldown = _cooldown_secs()
            quarantine_until = ts + cooldown
            _STATE[fp] = (first_ts, count, quarantine_until)
            retry_after = max(1, int(cooldown)) if cooldown > 0 else 0
            return "full_quarantine", retry_after
        _STATE[fp] = (first_ts, count, 0.0)
        return "normal", 0

    # Non-deny path: skip creating new entries.
    if entry is None:
        return "normal", 0

    if ts - first_ts > _window_secs():
        _STATE.pop(fp, None)
    return "normal", 0


def reset_state() -> None:
    _STATE.clear()


def reset_memory() -> None:  # backward compat for existing tests
    reset_state()


def is_enabled() -> bool:
    return _enabled()
