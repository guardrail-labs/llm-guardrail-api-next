from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerifierOutcome:
    allowed: bool
    reason: str
    provider: Optional[str] = None
