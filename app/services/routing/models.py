from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RoutingAction(str, Enum):
    ALLOW = "allow"
    CLARIFY = "clarify"
    BLOCK_INPUT_ONLY = "block_input_only"
    VERIFY_INTENT = "verify_intent"


class ClarifyStage(str, Enum):
    STAGE1 = "stage1"
    STAGE2 = "stage2"
    REWRITE_INTAKE = "rewrite_intake"


@dataclass(frozen=True)
class RoutingDecision:
    action: RoutingAction
    clarify_stage: Optional[ClarifyStage]
    message: Optional[str]
    reason_codes: List[str] = field(default_factory=list)
    attempt: int = 0
    near_duplicate: bool = False
