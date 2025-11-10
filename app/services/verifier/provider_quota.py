from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict

from app.settings import (
    VERIFIER_PROVIDER_QUOTA_DEFAULT_SKIP_S,
    VERIFIER_PROVIDER_QUOTA_MAX_SKIP_S,
)


@dataclass
class _QState:
    until_ts: float = 0.0


class QuotaSkipRegistry:
    """Tracks per-provider "skip until" timestamps derived from rate limit signals."""

    def __init__(self) -> None:
        self._states: Dict[str, _QState] = {}

    def is_skipped(self, name: str) -> bool:
        s = self._states.get(name)
        return bool(s and s.until_ts > time.time())

    def on_rate_limited(self, name: str, retry_after_s: float | None) -> float:
        base = VERIFIER_PROVIDER_QUOTA_DEFAULT_SKIP_S
        cap = VERIFIER_PROVIDER_QUOTA_MAX_SKIP_S
        dur = float(base if retry_after_s is None else retry_after_s)
        dur = max(1.0, min(dur, float(cap)))
        until = time.time() + dur
        self._states[name] = _QState(until_ts=until)
        return dur

    def clear(self, name: str) -> None:
        if name in self._states:
            self._states[name] = _QState(0.0)
