from __future__ import annotations

import time
from typing import Dict, List

_INCIDENTS: List[Dict[str, object]] = []


def record_incident(*, kind: str, tenant: str, bot: str, count: int, content_type: str) -> None:
    """Record an egress redaction incident."""
    try:
        _INCIDENTS.append(
            {
                "kind": kind,
                "tenant": tenant,
                "bot": bot,
                "count": int(count),
                "content_type": content_type,
                "ts": time.time(),
            }
        )
    except Exception:
        pass


def list_incidents() -> List[Dict[str, object]]:
    """Return a copy of recorded incidents."""
    return list(_INCIDENTS)
