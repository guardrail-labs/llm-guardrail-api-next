from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Tuple

# Thread-safe, per-process in-memory counters
_Q_LOCK = threading.RLock()
# minute window: key -> list[timestamps]
_MINUTE: Dict[str, list[float]] = {}
# daily counters: key -> (window_start_epoch, count)
_DAILY: Dict[str, Tuple[int, int]] = {}

# Default config via env (can be overridden per-app via request.app.state)
_ENV_ENABLED = (os.environ.get("QUOTA_ENABLED") or "false").lower() == "true"
_ENV_MODE = (os.environ.get("QUOTA_MODE") or "hard").lower()  # "hard"|"soft"
_ENV_PER_MINUTE = int(os.environ.get("QUOTA_PER_MINUTE") or "0")
_ENV_PER_DAY = int(os.environ.get("QUOTA_PER_DAY") or "0")


def _cfg(request: Any) -> Tuple[bool, str, int, int]:
    """
    Resolve (enabled, mode, per_min, per_day) with app.state overrides.
    """
    st = getattr(request, "app", None)
    s = getattr(st, "state", None)
    enabled = bool(getattr(s, "quota_enabled", _ENV_ENABLED))
    mode = str(getattr(s, "quota_mode", _ENV_MODE)).lower()
    per_min = int(getattr(s, "quota_per_minute", _ENV_PER_MINUTE))
    per_day = int(getattr(s, "quota_per_day", _ENV_PER_DAY))
    if mode not in ("hard", "soft"):
        mode = "hard"
    return enabled, mode, max(0, per_min), max(0, per_day)


def _key(tenant_id: str, bot_id: str) -> str:
    return f"{tenant_id}:{bot_id}"


def _prune_minute(win: list[float], now: float) -> None:
    cutoff = now - 60.0
    # in-place prune
    win[:] = [t for t in win if t >= cutoff]


def _day_window_start(ts: float) -> int:
    # Floor to UTC midnight for simplicity
    return int(ts // 86400) * 86400


def reset_quota_state() -> None:
    """Test/helper: clear all quota windows."""
    with _Q_LOCK:
        _MINUTE.clear()
        _DAILY.clear()


def quota_check_and_consume(request: Any, tenant_id: str, bot_id: str) -> Tuple[bool, int, str]:
    """
    Check quotas and, if allowed (or soft mode), consume one unit.

    Returns: (allowed, retry_after_secs, reason)
      - allowed: False only when enabled & mode=hard & over limit
      - retry_after_secs: suggested wait (60 for minute, secs-to-midnight for day)
      - reason: "minute" | "day" | ""
    """
    enabled, mode, per_min, per_day = _cfg(request)
    if not enabled or (per_min == 0 and per_day == 0):
        return True, 0, ""

    now = time.time()
    k = _key(tenant_id, bot_id)

    with _Q_LOCK:
        # minute window
        if per_min > 0:
            win = _MINUTE.setdefault(k, [])
            _prune_minute(win, now)
            if len(win) >= per_min:
                retry = 60
                if mode == "hard":
                    return False, retry, "minute"
                # soft: mark but still proceed
            else:
                win.append(now)

        # daily window
        if per_day > 0:
            start, cnt = _DAILY.get(k, (_day_window_start(now), 0))
            cur_start = _day_window_start(now)
            if start != cur_start:
                start, cnt = cur_start, 0
            if cnt >= per_day:
                # secs to next day window
                retry = (start + 86400) - int(now)
                if retry < 1:
                    retry = 1
                if mode == "hard":
                    # Rollback minute append if we did it above
                    if per_min > 0 and k in _MINUTE:
                        _prune_minute(_MINUTE[k], now)  # ensure accuracy
                        if _MINUTE[k]:
                            _MINUTE[k].pop()  # best effort
                    return False, retry, "day"
                # soft: fall through
            else:
                _DAILY[k] = (start, cnt + 1)
        else:
            # maintain minute window entry if only minute quota used
            if per_min > 0:
                _MINUTE.setdefault(k, [])  # already appended above if allowed

    return True, 0, ""
