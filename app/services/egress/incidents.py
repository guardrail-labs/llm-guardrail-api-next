from __future__ import annotations

import os
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Deque, Dict, List, Optional

DEFAULT_MAX = 200
_MAX = int(os.getenv("EGRESS_INCIDENT_MAX", str(DEFAULT_MAX)))

@dataclass
class EgressIncident:
    ts: str
    tenant: str
    bot: str
    redactions: int
    reasons: List[str]
    sample_hash: Optional[str] = None

_BUF: Deque[EgressIncident] = deque(maxlen=_MAX)
_LOCK = RLock()

def record_incident(tenant: str, bot: str, redactions: int, reasons: List[str]) -> None:
    if redactions <= 0:
        return
    with _LOCK:
        _BUF.appendleft(EgressIncident(
            ts=datetime.now(timezone.utc).isoformat(),
            tenant=tenant,
            bot=bot,
            redactions=redactions,
            reasons=reasons,
        ))

def list_incidents(
    *, tenant: Optional[str] = None, bot: Optional[str] = None, limit: int = 50
) -> List[Dict]:
    out: List[Dict] = []
    lim = max(1, min(limit, _MAX))
    with _LOCK:
        for item in _BUF:
            if tenant and item.tenant != tenant:
                continue
            if bot and item.bot != bot:
                continue
            out.append(asdict(item))
            if len(out) >= lim:
                break
    return out
