from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional

from app import settings

STAGE1_MESSAGE = "I’m not sure I can help with that — could you provide more context?"
STAGE2_MESSAGE = (
    "That doesn’t help me clarify what you need. Please try again, or would you like help "
    "submitting a safe request?"
)
REFUSAL_MESSAGE = (
    "I can’t help with that. Please try a different request, or ask for help with a safe one."
)


@dataclass
class ClarifyState:
    prompt_fingerprint: str
    attempt_count: int
    updated_at: float


_STATE: Dict[str, ClarifyState] = {}


def _now() -> float:
    return time.time()


def _ttl_seconds() -> int:
    return int(settings.CLARIFY_ATTEMPT_TTL_SECONDS)


def reset_state() -> None:
    _STATE.clear()


def track_attempt(
    prompt_fingerprint: str,
    *,
    increment: bool,
    now: Optional[float] = None,
) -> tuple[int, bool]:
    if not prompt_fingerprint:
        return 0, False

    ts = now if now is not None else _now()
    ttl = _ttl_seconds()
    entry = _STATE.get(prompt_fingerprint)

    if entry and ts - entry.updated_at > ttl:
        entry = None

    near_duplicate = bool(entry and entry.prompt_fingerprint == prompt_fingerprint)
    attempt_count = entry.attempt_count if entry else 0

    if increment:
        attempt_count += 1
        _STATE[prompt_fingerprint] = ClarifyState(
            prompt_fingerprint=prompt_fingerprint,
            attempt_count=attempt_count,
            updated_at=ts,
        )
    elif entry:
        entry.updated_at = ts
        _STATE[prompt_fingerprint] = entry

    return attempt_count, near_duplicate


def stage_message(stage: int) -> str:
    if stage == 2:
        return STAGE2_MESSAGE
    return STAGE1_MESSAGE
