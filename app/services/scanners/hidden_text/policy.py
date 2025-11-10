from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from app.settings import (
    HIDDEN_TEXT_CLARIFY_REASONS,
    HIDDEN_TEXT_DENY_REASONS,
    HIDDEN_TEXT_FORMATS,
    HIDDEN_TEXT_MIN_MATCH,
    HIDDEN_TEXT_POLICY,
)
from app.telemetry.metrics import inc_hidden_text_action


def _norm_list(s: str) -> List[str]:
    return [t.strip().lower() for t in (s or "").split(",") if t.strip()]


def _format_allowed(fmt: str) -> bool:
    allowed = _norm_list(HIDDEN_TEXT_FORMATS)
    return (not allowed) or (fmt.lower() in allowed)


def decide_for_hidden_reasons(fmt: str, reasons: Iterable[str]) -> Tuple[Optional[str], List[str]]:
    """
    Returns (action, matched_reasons). action in {"deny","clarify",None}
    - Applies MIN_MATCH threshold per action.
    - deny reasons take precedence over clarify.
    """
    if not HIDDEN_TEXT_POLICY or not _format_allowed(fmt):
        return None, []

    r = [str(x or "").lower() for x in reasons if x]
    if not r:
        return None, []

    deny = _norm_list(HIDDEN_TEXT_DENY_REASONS)
    clar = _norm_list(HIDDEN_TEXT_CLARIFY_REASONS)

    matched_deny = sorted({x for x in r if x in deny})
    if len(matched_deny) >= max(1, HIDDEN_TEXT_MIN_MATCH):
        for m in matched_deny:
            inc_hidden_text_action(fmt, m, "deny")
        return "deny", matched_deny

    matched_clar = sorted({x for x in r if x in clar})
    if len(matched_clar) >= max(1, HIDDEN_TEXT_MIN_MATCH):
        for m in matched_clar:
            inc_hidden_text_action(fmt, m, "clarify")
        return "clarify", matched_clar

    return None, []
