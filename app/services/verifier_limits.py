from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict


class VerifierLimitError(Exception):
    """Base class for verifier limit related errors."""


class VerifierTimeoutError(VerifierLimitError):
    """Raised when a verifier call exceeds the allotted time."""


class VerifierBudgetExceeded(VerifierLimitError):
    """Raised when a tenant exceeds its daily token budget."""


class VerifierCircuitOpen(VerifierLimitError):
    """Raised when the circuit breaker is open."""


@dataclass
class VerifierContext:
    tenant_id: str
    bot_id: str


def new_incident_id() -> str:
    return str(uuid.uuid4())


class VerifierEnforcer:
    """Lightweight stubbed enforcer for verifier limits."""

    def __init__(
        self,
        *,
        max_tokens_per_request: int,
        daily_budget: int,
        breaker_max_failures: int,
        breaker_window_s: int,
        breaker_cooldown_s: int,
    ) -> None:
        # Real implementations would store these values and enforce limits.
        self.max_tokens_per_request = max_tokens_per_request
        self.daily_budget = daily_budget
        self.breaker_max_failures = breaker_max_failures
        self.breaker_window_s = breaker_window_s
        self.breaker_cooldown_s = breaker_cooldown_s

    def precheck(self, ctx: VerifierContext, est_tokens: int) -> None:
        """Validate request before executing verifier."""

    def post_consume(self, ctx: VerifierContext, used: int) -> None:
        """Record consumed tokens after verifier execution."""

    def on_success(self, ctx: VerifierContext) -> None:
        """Record a successful verifier run."""

    def on_failure(self, ctx: VerifierContext) -> Dict[str, Any]:
        """Record a failed verifier run and return state info."""
        return {}

