"""
Abuse control engine: strikes → escalation → headers.

Modes:
- allow
- block_input_only          (per-prompt block, session still usable)
- execute_locked            (disable tool/agent execution; allow summarize/redact/policy_check)
 - full_quarantine           (block all LLM ops; client gets HTTP 429 + Retry-After)

This module is self-contained (no external deps), Ruff-clean, and mypy-safe.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple

Decision = Literal["allow", "block_input_only", "execute_locked", "full_quarantine"]


# -----------------------------
# Config
# -----------------------------
@dataclass(frozen=True)
class AbuseConfig:
    """Strike window and escalation tiers (threshold, mode, cooldown_sec)."""

    strike_window_sec: int = 600
    tiers: List[Tuple[int, Decision, int]] = field(
        default_factory=lambda: [
            (3, "execute_locked", 3600),    # 3 strikes in window -> 1h execute lock
            (5, "full_quarantine", 21600),  # 5 strikes in window -> 6h quarantine
        ]
    )

    @staticmethod
    def _parse_mode(raw: str) -> Decision:
        m = raw.strip().lower()
        if m in ("allow", "block_input_only", "execute_locked", "full_quarantine"):
            return m  # type: ignore[return-value]
        raise ValueError(f"Invalid abuse mode: {raw}")

    @classmethod
    def from_env(cls) -> "AbuseConfig":
        win = int(os.getenv("ABUSE_STRIKE_WINDOW_SEC", "600"))
        t1_thresh = int(os.getenv("ABUSE_TIER1_THRESHOLD", "3"))
        t1_mode = cls._parse_mode(os.getenv("ABUSE_TIER1_MODE", "execute_locked"))
        t1_cool = int(os.getenv("ABUSE_TIER1_COOLDOWN_SEC", "3600"))
        t2_thresh = int(os.getenv("ABUSE_TIER2_THRESHOLD", "5"))
        t2_mode = cls._parse_mode(os.getenv("ABUSE_TIER2_MODE", "full_quarantine"))
        t2_cool = int(os.getenv("ABUSE_TIER2_COOLDOWN_SEC", "21600"))
        return cls(
            strike_window_sec=win,
            tiers=[(t1_thresh, t1_mode, t1_cool), (t2_thresh, t2_mode, t2_cool)],
        )


# -----------------------------
# Subject identity (hashed)
# -----------------------------
@dataclass(frozen=True)
class Subject:
    api_key_hash: str
    ip_hash: str
    org_id: Optional[str] = None
    session_id: Optional[str] = None

    def key(self) -> str:
        return "|".join(
            filter(
                None,
                [
                    self.api_key_hash,
                    self.ip_hash,
                    self.org_id or "",
                    self.session_id or "",
                ],
            )
        )


# -----------------------------
# Storage (in-memory, pluggable)
# -----------------------------
class InMemoryStore:
    def __init__(self) -> None:
        self._strikes: Dict[str, List[float]] = {}
        self._bans: Dict[str, Tuple[Decision, float]] = {}

    def add_strike(self, sub: Subject, at: float) -> None:
        k = sub.key()
        self._strikes.setdefault(k, []).append(at)

    def strikes_in_window(self, sub: Subject, now: float, window_sec: int) -> int:
        k = sub.key()
        times = self._strikes.get(k, [])
        pruned = [t for t in times if now - t <= window_sec]
        self._strikes[k] = pruned
        return len(pruned)

    def set_ban(self, sub: Subject, mode: Decision, until_ts: float) -> None:
        self._bans[sub.key()] = (mode, until_ts)

    def get_ban(self, sub: Subject) -> Optional[Tuple[Decision, float]]:
        return self._bans.get(sub.key())


# -----------------------------
# Engine
# -----------------------------
class AbuseEngine:
    def __init__(
        self,
        store: Optional[InMemoryStore] = None,
        cfg: Optional[AbuseConfig] = None,
    ) -> None:
        self.store = store or InMemoryStore()
        self.cfg = cfg or AbuseConfig.from_env()

    def _now(self) -> float:
        return time.time()

    def current_mode(self, sub: Subject, now: Optional[float] = None) -> Decision:
        now = now if now is not None else self._now()
        ban = self.store.get_ban(sub)
        if not ban:
            return "allow"
        mode, until_ts = ban
        if until_ts > now:
            return mode
        return "allow"

    def record_unsafe(self, sub: Subject, now: Optional[float] = None) -> Decision:
        """
        Called when a harmful/unsafe intent is confirmed for this request.
        Returns the *decision* to apply right now (per-prompt block or escalated mode).
        """
        now = now if now is not None else self._now()
        self.store.add_strike(sub, now)
        count = self.store.strikes_in_window(sub, now, self.cfg.strike_window_sec)

        # escalate to the highest tier satisfied by count
        decided: Decision = "block_input_only"
        for threshold, mode, cooldown in sorted(self.cfg.tiers, key=lambda t: t[0]):
            if count >= threshold:
                self.store.set_ban(sub, mode, now + cooldown)
                decided = mode
        return decided

    def retry_after_seconds(self, sub: Subject, now: Optional[float] = None) -> int:
        now = now if now is not None else self._now()
        ban = self.store.get_ban(sub)
        if not ban:
            return 0
        _, until_ts = ban
        remain = int(max(0.0, until_ts - now))
        return remain


# -----------------------------
# Headers & incident_id
# -----------------------------
def generate_incident_id(now: Optional[float] = None) -> str:
    ts = time.gmtime(now if now is not None else time.time())
    stamp = f"{ts.tm_year:04d}-{ts.tm_mon:02d}-{ts.tm_mday:02d}"
    rand = uuid.uuid4().hex[:6].upper()
    return f"gr-{stamp}-{rand}"


def decision_headers(
    decision: Decision,
    incident_id: str,
    retry_after_s: Optional[int] = None,
) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Incident-ID": incident_id,
    }
    if decision in ("execute_locked", "full_quarantine"):
        headers["X-Guardrail-Mode"] = decision
    if decision == "full_quarantine" and retry_after_s and retry_after_s > 0:
        headers["Retry-After"] = str(retry_after_s)
    return headers

