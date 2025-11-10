from __future__ import annotations

import time
from threading import RLock
from typing import Dict, Optional

from app.settings import (
    VERIFIER_EGRESS_REUSE_ENABLED,
    VERIFIER_EGRESS_REUSE_TTL_SECONDS,
)

Outcome = str  # "safe" | "unsafe"


class _MemReuse:
    def __init__(self, ttl_s: int) -> None:
        self._ttl = max(1, int(ttl_s))
        self._data: Dict[str, tuple[Outcome, float]] = {}
        self._lock = RLock()

    def _now(self) -> float:
        return time.time()

    def get(self, key: str) -> Optional[Outcome]:
        now = self._now()
        with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            outcome, ts = v
            if now - ts > self._ttl:
                self._data.pop(key, None)
                return None
            return outcome

    def set(self, key: str, outcome: Outcome) -> None:
        if outcome not in ("safe", "unsafe"):
            return
        with self._lock:
            self._data[key] = (outcome, self._now())

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


ENABLED = VERIFIER_EGRESS_REUSE_ENABLED
_TTL = VERIFIER_EGRESS_REUSE_TTL_SECONDS
_MEM = _MemReuse(_TTL)


def make_key(
    request_id: str,
    tenant: str,
    bot: str,
    policy_version: str,
    fingerprint: str,
) -> str:
    rid = request_id or "unknown"
    t = tenant or "unknown-tenant"
    b = bot or "unknown-bot"
    pv = policy_version or "unknown-policy"
    fp = fingerprint or "unknown-fp"
    return f"reuse:v1:{rid}:{t}:{b}:{pv}:{fp}"


def get(key: str) -> Optional[Outcome]:
    return _MEM.get(key)


def set_decisive(key: str, outcome: Outcome) -> None:
    _MEM.set(key, outcome)


def reset_memory() -> None:
    _MEM.clear()
