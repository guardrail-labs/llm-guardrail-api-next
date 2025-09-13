from __future__ import annotations

import os
import time
from typing import Dict, List, Literal

Mode = Literal["normal", "execute_locked", "full_quarantine"]


def _WINDOW() -> int:
    return int(os.getenv("ESCALATION_WINDOW_SEC", "300") or "300")


def _T1() -> int:
    return int(os.getenv("ESCALATION_TIER1_THRESHOLD", "3") or "3")


def _T2() -> int:
    return int(os.getenv("ESCALATION_TIER2_THRESHOLD", "10") or "10")


def _COOLDOWN() -> int:
    return int(os.getenv("ESCALATION_COOLDOWN_SEC", "300") or "300")


def _ENABLED() -> bool:
    return os.getenv("ESCALATION_ENABLED", "0") == "1"

# in-memory counters: fp -> timestamps of unsafe ingress decisions
_UNSAFE: Dict[str, List[int]] = {}
# cooldown map: fp -> until_ts for full_quarantine
_COOLDOWN_UNTIL: Dict[str, int] = {}

def record_unsafe(fp: str) -> None:
    if not _ENABLED():
        return
    now = int(time.time())
    buf = _UNSAFE.setdefault(fp, [])
    buf.append(now)
    # prune old
    cutoff = now - _WINDOW()
    while buf and buf[0] < cutoff:
        buf.pop(0)

def current_mode(fp: str) -> Mode:
    if not _ENABLED():
        return "normal"
    now = int(time.time())
    # tier2 cooldown check
    until = _COOLDOWN_UNTIL.get(fp, 0)
    if until > now:
        return "full_quarantine"

    buf = _UNSAFE.get(fp, [])
    n = len(buf)
    if n >= _T2():
        # enter full_quarantine and set cooldown
        _COOLDOWN_UNTIL[fp] = now + _COOLDOWN()
        return "full_quarantine"
    if n >= _T1():
        return "execute_locked"
    return "normal"

def reset_memory() -> None:
    _UNSAFE.clear()
    _COOLDOWN_UNTIL.clear()
