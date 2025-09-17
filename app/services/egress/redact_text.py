from __future__ import annotations

from typing import Dict, Tuple

from app.services import policy_redact


def redact_text(body: str) -> Tuple[str, Dict[str, int]]:
    """Apply policy redact rules to *body* and return (text, counts)."""

    rules = policy_redact.get_redact_rules()
    out = body
    counts: Dict[str, int] = {}

    for rule in rules:
        rx = rule.compile()
        new_text, n = rx.subn(rule.replacement, out)
        if n:
            counts[rule.rule_id] = counts.get(rule.rule_id, 0) + n
            out = new_text

    return out, counts
