from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from app.metrics_verifier import verifier_events
from app.verifier.base import (
    Verifier,
    VerifierTimeout,
    VerifyInput,
    VerifyResult,
    decision_headers,
    new_incident_id,
)


@dataclass
class _Health:
    ok: bool
    ts: float


class VerifierManager:
    """
    Provider-agnostic verifier manager with health cache and failover.
    """

    def __init__(self, providers: Sequence[Verifier], health_ttl_s: float = 10.0) -> None:
        self._providers: List[Verifier] = list(providers)
        # Key health by object identity to avoid name collisions across instances.
        self._health: Dict[int, _Health] = {}
        self._ttl = health_ttl_s
        self._rr = 0

    @staticmethod
    def _key(p: Verifier) -> int:
        # Object identity is stable for the life of the instance.
        return id(p)

    def _is_healthy(self, p: Verifier, now: float) -> bool:
        k = self._key(p)
        h = self._health.get(k)
        if h and now - h.ts < self._ttl:
            return h.ok
        ok = False
        try:
            ok = bool(p.health())
        except Exception:
            ok = False
        self._health[k] = _Health(ok=ok, ts=now)
        return ok

    def _mark_unhealthy(self, p: Verifier) -> None:
        self._health[self._key(p)] = _Health(ok=False, ts=time.time())

    def verify_with_failover(
        self, req: VerifyInput, timeout_s: float = 5.0
    ) -> Tuple[VerifyResult, Dict[str, str], str]:
        """
        Returns: (result, headers, provider_name_or_default)
        On total outage, returns default-block with incident headers.
        """
        now = time.time()
        n = len(self._providers)
        if n == 0:
            inc = new_incident_id()
            verifier_events.labels("none", "outage").inc()
            hdr = decision_headers(False, mode="block_input", incident_id=inc)
            return VerifyResult(False, "no_providers", 0.0), hdr, "none"

        # Round-robin start
        start = self._rr % n
        self._rr = (self._rr + 1) % n

        # First pass: pick healthy providers
        order: List[Verifier] = []
        for i in range(n):
            p = self._providers[(start + i) % n]
            if self._is_healthy(p, now):
                order.append(p)
        # Fallback: if none are healthy per cache, try all anyway
        if not order:
            order = list(self._providers)

        last_err: Optional[str] = None

        for p in order:
            try:
                res = p.verify(req, timeout_s=timeout_s)
                verifier_events.labels(p.name, "success").inc()
                mode = "allow" if res.allowed else "block_input"
                hdr = decision_headers(res.allowed, mode=mode, incident_id=None)
                return res, hdr, p.name
            except VerifierTimeout:
                last_err = "timeout"
                self._mark_unhealthy(p)
                verifier_events.labels(p.name, "timeout").inc()
            except Exception:
                last_err = "error"
                self._mark_unhealthy(p)
                verifier_events.labels(p.name, "error").inc()

        # All failed or unhealthy: default-block with incident id.
        inc = new_incident_id()
        provider = "failover"
        verifier_events.labels(provider, "outage").inc()
        hdr = decision_headers(False, mode="block_input", incident_id=inc)
        res = VerifyResult(allowed=False, reason=last_err or "outage", confidence=0.0)
        return res, hdr, provider
