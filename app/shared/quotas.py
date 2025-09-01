from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Tuple

from fastapi import Request

_RATE_LOCK = threading.RLock()
_BUCKETS: Dict[str, List[float]] = {}  # per-tenant:bot rolling window timestamps
_LAST_RATE_CFG: Tuple[bool, int, int] = (False, 60, 60)
_LAST_APP_ID: int | None = None  # reset buckets when app instance changes


def _key(tenant_id: str, bot_id: str) -> str:
    return f"{tenant_id}:{bot_id}"


def _bucket_for(key: str) -> List[float]:
    win = _BUCKETS.get(key)
    if win is None:
        win = []
        _BUCKETS[key] = win
    return win


def _cfg_from_app_or_env(request: Request) -> Tuple[bool, int, int]:
    """
    Prefer app.state for testability/override:
      - quota_enabled: bool
      - quota_per_minute: int
      - quota_burst: int (default = per_minute)
    Fallback to env:
      QUOTA_ENABLED, QUOTA_PER_MINUTE, QUOTA_BURST
    """
    st = getattr(request.app, "state", None)
    if st and hasattr(st, "quota_enabled"):
        enabled = bool(getattr(st, "quota_enabled"))
        per_min = int(getattr(st, "quota_per_minute", 60))
        burst = int(getattr(st, "quota_burst", per_min))
        return enabled, per_min, burst

    enabled = (os.environ.get("QUOTA_ENABLED") or "false").lower() == "true"
    per_min = int(os.environ.get("QUOTA_PER_MINUTE") or "60")
    burst = int(os.environ.get("QUOTA_BURST") or str(per_min))
    return enabled, per_min, burst


def check_and_consume(request: Request, tenant_id: str, bot_id: str) -> Tuple[bool, int]:
    """
    Sliding 60s window per tenant:bot with burst.
    Returns (allowed, retry_after_seconds).
    """
    global _LAST_RATE_CFG, _LAST_APP_ID

    app_id = id(request.app)
    if _LAST_APP_ID != app_id:
        with _RATE_LOCK:
            _BUCKETS.clear()
            _LAST_APP_ID = app_id

    cfg = _cfg_from_app_or_env(request)
    if cfg != _LAST_RATE_CFG:
        with _RATE_LOCK:
            _BUCKETS.clear()
            _LAST_RATE_CFG = cfg

    enabled, per_min, burst = cfg
    if not enabled:
        return True, 0

    now = time.time()
    cutoff = now - 60.0
    key = _key(tenant_id, bot_id)

    with _RATE_LOCK:
        win = _bucket_for(key)
        # purge old
        win[:] = [t for t in win if t >= cutoff]
        if len(win) >= burst:
            # retry when oldest-in-window expires
            oldest = min(win) if win else now
            retry_after = max(1, int((oldest + 60.0) - now))
            return False, retry_after
        win.append(now)
        return True, 0
