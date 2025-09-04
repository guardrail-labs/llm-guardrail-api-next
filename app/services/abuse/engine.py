from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Literal, Optional

Decision = Literal["allow", "block_input_only", "execute_locked", "full_quarantine"]

@dataclass
class AbuseConfig:
    strike_window_sec: int = 600
    tiers = (
        (3, "execute_locked", 3600),   # 3 strikes -> 1h lock execution
        (5, "full_quarantine", 21600), # 5 strikes -> 6h full quarantine
    )

@dataclass
class Subject:
    api_key_hash: str
    ip_hash: str
    org_id: str | None = None
    session_id: str | None = None

class InMemoryStore:
    def __init__(self):
        self._strikes: Dict[str, list[float]] = {}
        self._bans: Dict[str, float] = {}  # until_ts per subject key

    def key(self, s: Subject) -> str:
        return "|".join(
            filter(None, [s.api_key_hash, s.ip_hash, s.org_id or "", s.session_id or ""])
        )

    def add_strike(self, s: Subject, now: float) -> int:
        k = self.key(s)
        self._strikes.setdefault(k, []).append(now)
        return len(self._strikes[k])

    def strikes_in_window(self, s: Subject, now: float, window_sec: int) -> int:
        k = self.key(s)
        wins = [t for t in self._strikes.get(k, []) if now - t <= window_sec]
        self._strikes[k] = wins
        return len(wins)

    def set_ban(self, s: Subject, until_ts: float):
        self._bans[self.key(s)] = until_ts

    def ban_until(self, s: Subject) -> float:
        return self._bans.get(self.key(s), 0.0)

class AbuseEngine:
    def __init__(self, store: Optional[InMemoryStore] = None, cfg: Optional[AbuseConfig] = None):
        self.store = store or InMemoryStore()
        self.cfg = cfg or AbuseConfig()

    def record_unsafe(self, s: Subject, now: Optional[float] = None) -> Decision:
        now = now or time.time()
        self.store.add_strike(s, now)
        count = self.store.strikes_in_window(s, now, self.cfg.strike_window_sec)
        # Escalate
        for threshold, mode, cooldown in self.cfg.tiers:
            if count >= threshold:
                self.store.set_ban(s, now + cooldown)
                return mode  # type: ignore[return-value]
        return "block_input_only"

    def current_mode(self, s: Subject, now: Optional[float] = None) -> Decision:
        now = now or time.time()
        until = self.store.ban_until(s)
        if until > now:
            # need to know which mode was set; we can store separately;
            # for now infer by remaining time window
            return "execute_locked"  # minimal; caller may store explicit mode externally
        return "allow"


def decision_headers(
    decision: Decision, incident_id: str, retry_after_s: int | None = None
) -> Dict[str, str]:
    headers = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Incident-ID": incident_id,
    }
    if decision in ("execute_locked", "full_quarantine"):
        headers["X-Guardrail-Mode"] = decision
    if decision == "full_quarantine" and retry_after_s:
        headers["Retry-After"] = str(retry_after_s)
    return headers
