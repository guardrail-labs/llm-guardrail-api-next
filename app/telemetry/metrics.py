from __future__ import annotations

import threading
from typing import Dict

# ----------------------------
# Decision-family counters
# ----------------------------
_FAMILY_LOCK = threading.RLock()
_FAMILY: Dict[str, float] = {
    "allow": 0.0,
    "block": 0.0,
    "sanitize": 0.0,
    "verify": 0.0,
}

def inc_decision_family(name: str, by: float = 1.0) -> None:
    key = (name or "").lower().strip()
    if key not in _FAMILY:
        return
    with _FAMILY_LOCK:
        _FAMILY[key] += float(by)

def get_decisions_family_total(name: str) -> float:
    key = (name or "").lower().strip()
    if key not in _FAMILY:
        return 0.0
    with _FAMILY_LOCK:
        return float(_FAMILY[key])

def get_all_family_totals() -> Dict[str, float]:
    with _FAMILY_LOCK:
        return {k: float(v) for k, v in _FAMILY.items()}

# ----------------------------
# Rate-limited counter
# ----------------------------
_RATE_LIMIT_LOCK = threading.RLock()
_RATE_LIMITED_TOTAL: float = 0.0

def inc_rate_limited(by: float = 1.0) -> None:
    global _RATE_LIMITED_TOTAL
    with _RATE_LIMIT_LOCK:
        _RATE_LIMITED_TOTAL += float(by)

def get_rate_limited_total() -> float:
    with _RATE_LIMIT_LOCK:
        return float(_RATE_LIMITED_TOTAL)
