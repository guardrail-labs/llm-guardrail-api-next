"""Base guard protocol definitions."""

from __future__ import annotations

from typing import Any, Dict, Protocol, TypedDict


class GuardDecision(TypedDict):
    """Structured decision emitted by ingress/egress guards."""

    action: str  # "allow" | "clarify" | "block"
    mode: str  # "normal" | "block_input_only" | "execute_locked"
    incident_id: str
    reason: str
    details: Dict[str, Any]


class GuardArm(Protocol):
    """Protocol implemented by guard arms."""

    async def evaluate(self, ctx: Dict[str, Any]) -> GuardDecision: ...


class GuardException(Exception):
    """Generic guard failure wrapper."""


__all__ = ["GuardDecision", "GuardArm", "GuardException"]
