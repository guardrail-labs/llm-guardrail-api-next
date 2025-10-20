from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Protocol


@dataclass(frozen=True)
class VerifyInput:
    text: str
    intent: Optional[str] = None  # e.g., "code_exec", "pii_leak", etc.


@dataclass(frozen=True)
class VerifyResult:
    allowed: bool
    reason: str
    confidence: float  # 0..1


class VerifierError(Exception):
    pass


class VerifierTimeout(VerifierError):
    pass


class Verifier(Protocol):
    name: str

    def health(self) -> bool:
        ...

    def verify(self, req: VerifyInput, timeout_s: float = 5.0) -> VerifyResult:
        ...


def new_incident_id() -> str:
    return str(uuid.uuid4())


def decision_headers(
    allowed: bool, mode: str = "allow", incident_id: Optional[str] = None
) -> Dict[str, str]:
    """
    Utility to standardize decision headers for callers.
    mode: "allow" | "clarify" | "execute_locked" | "block_input"
    """
    headers = {
        "X-Guardrail-Decision": "allow" if allowed else "block-input",
        "X-Guardrail-Mode": mode,
    }
    if incident_id:
        headers["X-Guardrail-Incident-ID"] = incident_id
    return headers
