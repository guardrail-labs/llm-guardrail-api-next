from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict


@dataclass
class _State:
    fails: int = 0
    opened_at: float = 0.0
    last_fail_ts: float = 0.0
    half_open: bool = False


class ProviderBreakerRegistry:
    """
    Very lightweight, per-process breaker store keyed by provider name.
    - Open after N failures within WINDOW seconds.
    - Stay open for COOLDOWN seconds.
    - After cooldown, allow a single trial (half-open).
    - Close on success; otherwise re-open.
    """

    def __init__(self, max_fails: int, window_s: int, cooldown_s: int) -> None:
        self._max_fails = max(1, int(max_fails))
        self._window_s = max(1, int(window_s))
        self._cooldown_s = max(1, int(cooldown_s))
        self._states: Dict[str, _State] = {}

    def _now(self) -> float:
        return time.time()

    def _state(self, name: str) -> _State:
        return self._states.setdefault(name, _State())

    def is_open(self, name: str) -> bool:
        st = self._state(name)
        if st.opened_at <= 0:
            return False
        # Cooldown over -> half-open probe allowed
        if self._now() - st.opened_at >= self._cooldown_s:
            st.half_open = True
            st.opened_at = 0.0
            st.fails = 0
            return False
        return True

    def on_failure(self, name: str) -> bool:
        """
        Returns True if this failure caused the breaker to open.
        """
        st = self._state(name)
        now = self._now()
        # decay fails outside window
        if now - st.last_fail_ts > self._window_s:
            st.fails = 0
        st.fails += 1
        st.last_fail_ts = now
        if st.fails >= self._max_fails:
            st.opened_at = now
            st.half_open = False
            return True
        return False

    def on_success(self, name: str) -> None:
        st = self._state(name)
        st.fails = 0
        st.opened_at = 0.0
        st.half_open = False
