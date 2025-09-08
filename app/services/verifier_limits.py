from __future__ import annotations

import uuid
from dataclasses import dataclass


class VerifierLimitError(Exception):
    """Base verifier limit error."""


class VerifierBudgetExceeded(VerifierLimitError):
    """Raised when the daily token budget is exhausted."""


class VerifierCircuitOpen(VerifierLimitError):
    """Raised when the circuit breaker is open."""


class VerifierTimeoutError(VerifierLimitError):
    """Raised when a verifier call times out."""


@dataclass
class VerifierContext:
    tenant_id: str
    bot_id: str


class VerifierEnforcer:
    """Minimal token/budget enforcer stub."""

    def __init__(
        self,
        *,
        max_tokens_per_request: int,
        daily_budget: int,
        breaker_max_failures: int,
        breaker_window_s: int,
        breaker_cooldown_s: int,
    ) -> None:
        self.max_tokens_per_request = max_tokens_per_request
        self.daily_budget = daily_budget
        self.tokens_used = 0

    def precheck(self, ctx: VerifierContext, tokens: int) -> None:  # noqa: ARG002
        if tokens > self.max_tokens_per_request:
            raise VerifierLimitError("max tokens exceeded")
        if self.tokens_used + tokens > self.daily_budget:
            raise VerifierBudgetExceeded("daily budget exceeded")

    def post_consume(self, ctx: VerifierContext, tokens: int) -> None:  # noqa: ARG002
        self.tokens_used += tokens

    def on_success(self, ctx: VerifierContext) -> None:  # noqa: ARG002
        return None

    def on_failure(self, ctx: VerifierContext) -> str:  # noqa: ARG002
        return "closed"


def new_incident_id() -> str:
    return str(uuid.uuid4())

