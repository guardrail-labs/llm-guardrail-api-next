from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Protocol

Label = Literal["safe", "unclear", "unsafe"]


@dataclass
class Verdict:
    label: Label
    confidence: float
    provider: str
    meta: Dict[str, Any]


class VerifierAdapter(Protocol):
    def classify(self, text: str, context: Dict[str, Any] | None = None) -> Verdict: ...
