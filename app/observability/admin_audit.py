from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger("admin_audit")

_RING: List[Dict[str, Any]] = []
_RING_MAX = 500
_LOCK = threading.RLock()


def _now_ms() -> int:
    return int(time.time() * 1000)


def record(
    *,
    action: str,
    actor_email: Optional[str],
    actor_role: Optional[str],
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    outcome: str = "ok",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evt = {
        "ts_ms": _now_ms(),
        "action": action,
        "actor_email": actor_email,
        "actor_role": actor_role,
        "tenant": tenant,
        "bot": bot,
        "outcome": outcome,
        "meta": meta or {},
    }
    try:
        _log.info(json.dumps(evt, separators=(",", ":"), ensure_ascii=False))
    except Exception:
        pass
    with _LOCK:
        _RING.append(evt)
        if len(_RING) > _RING_MAX:
            del _RING[: len(_RING) - _RING_MAX]
    return evt


def recent(limit: int = 50) -> List[Dict[str, Any]]:
    clamped = max(1, min(limit, _RING_MAX))
    with _LOCK:
        return list(_RING[-clamped:])
