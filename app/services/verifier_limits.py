from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# ---- Typed outcomes / errors -------------------------------------------------

class VerifierLimitError(RuntimeError): ...
class VerifierTimeoutError(VerifierLimitError): ...
class VerifierBudgetExceeded(VerifierLimitError): ...
class VerifierCircuitOpen(VerifierLimitError): ...

@dataclass(frozen=True)
class VerifierContext:
    tenant_id: str
    bot_id: str

# ---- Token budget (simple in-mem, swappable for Redis later) -----------------

class BudgetLedger:
    """
    Tracks token spend per (tenant_id, bot_id, day_epoch). Thread-safe in single
    worker; for multi-worker, replace with Redis (same interface).
    """
    def __init__(self, daily_budget: int) -> None:
        self.daily_budget = max(0, int(daily_budget))
        self._buckets: Dict[Tuple[str, str, int], int] = {}

    @staticmethod
    def _day_epoch(now_s: Optional[float] = None) -> int:
        # UTC day epoch (00:00:00 UTC boundaries)
        ts = int(now_s if now_s is not None else time.time())
        return ts // 86400

    def get(self, ctx: VerifierContext, now_s: Optional[float] = None) -> int:
        k = (ctx.tenant_id, ctx.bot_id, self._day_epoch(now_s))
        return self._buckets.get(k, 0)

    def can_consume(self, ctx: VerifierContext, tokens: int, now_s: Optional[float] = None) -> bool:
        used = self.get(ctx, now_s)
        return (used + max(0, tokens)) <= self.daily_budget

    def consume(self, ctx: VerifierContext, tokens: int, now_s: Optional[float] = None) -> int:
        tokens = max(0, tokens)
        k = (ctx.tenant_id, ctx.bot_id, self._day_epoch(now_s))
        used = self._buckets.get(k, 0) + tokens
        if used > self.daily_budget:
            raise VerifierBudgetExceeded(f"Daily budget exceeded: {used}/{self.daily_budget}")
        self._buckets[k] = used
        return used

# ---- Circuit breaker ---------------------------------------------------------

class CircuitBreaker:
    """
    Per-(tenant,bot) failure breaker. Opens after N failures within window,
    stays open for cooldown, then half-opens.
    """
    def __init__(self, max_failures: int, window_s: int, cooldown_s: int) -> None:
        self.max_failures = max(1, int(max_failures))
        self.window_s = max(1, int(window_s))
        self.cooldown_s = max(1, int(cooldown_s))
        self._state: Dict[Tuple[str, str], Dict[str, float]] = {}
        # state keys: failures, first_ts, open_until (if open)

    def _now(self) -> float:
        return time.time()

    def _key(self, ctx: VerifierContext) -> Tuple[str, str]:
        return (ctx.tenant_id, ctx.bot_id)

    def is_open(self, ctx: VerifierContext) -> bool:
        st = self._state.get(self._key(ctx))
        if not st:
            return False
        open_until = st.get("open_until", 0.0)
        if open_until and self._now() < open_until:
            return True
        # past cooldown -> close
        if open_until and self._now() >= open_until:
            st["failures"] = 0
            st["first_ts"] = 0.0
            st["open_until"] = 0.0
        return False

    def record_success(self, ctx: VerifierContext) -> None:
        self._state[self._key(ctx)] = {"failures": 0, "first_ts": 0.0, "open_until": 0.0}

    def record_failure(self, ctx: VerifierContext) -> str:
        now = self._now()
        k = self._key(ctx)
        st = self._state.setdefault(k, {"failures": 0, "first_ts": now, "open_until": 0.0})

        # reset window if expired
        if now - st["first_ts"] > self.window_s:
            st["failures"] = 0
            st["first_ts"] = now

        st["failures"] += 1
        if st["failures"] >= self.max_failures:
            st["open_until"] = now + self.cooldown_s
            return "open"
        return "closed"

# ---- Limit enforcement facade ------------------------------------------------

@dataclass
class EnforcedCallResult:
    status: str                    # "safe" | "unsafe" | "ambiguous" | "error"
    reason: str
    tokens_used: int
    incident_id: Optional[str] = None

class VerifierEnforcer:
    """
    Enforces per-request token cap, daily budget, timeout window (the outer
    caller should ensure the model call is timeboxed), and circuit breaker.
    """
    def __init__(
        self,
        *,
        max_tokens_per_request: int,
        daily_budget: int,
        breaker_max_failures: int,
        breaker_window_s: int,
        breaker_cooldown_s: int,
    ) -> None:
        self.max_tokens_per_request = max(1, int(max_tokens_per_request))
        self.ledger = BudgetLedger(daily_budget)
        self.breaker = CircuitBreaker(breaker_max_failures, breaker_window_s, breaker_cooldown_s)

    def precheck(self, ctx: VerifierContext, est_tokens: int) -> None:
        if est_tokens > self.max_tokens_per_request:
            raise VerifierLimitError(
                f"Per-request token cap exceeded: {est_tokens}/{self.max_tokens_per_request}"
            )
        if self.breaker.is_open(ctx):
            raise VerifierCircuitOpen("Circuit open for verifier")
        if not self.ledger.can_consume(ctx, est_tokens):
            raise VerifierBudgetExceeded("Daily token budget exhausted")

    def post_consume(self, ctx: VerifierContext, used_tokens: int) -> int:
        return self.ledger.consume(ctx, used_tokens)

    def on_success(self, ctx: VerifierContext) -> None:
        self.breaker.record_success(ctx)

    def on_failure(self, ctx: VerifierContext) -> str:
        return self.breaker.record_failure(ctx)

def new_incident_id() -> str:
    return str(uuid.uuid4())
