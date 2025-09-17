from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

try:  # pragma: no cover - optional dependency wiring
    from app.services import policy as _policy
except Exception:  # pragma: no cover
    _policy = None  # type: ignore


class RedactRule:
    __slots__ = ("rule_id", "pattern", "replacement", "flags")

    def __init__(
        self,
        rule_id: str,
        pattern: str,
        replacement: str = "█",
        flags: int = 0,
    ) -> None:
        self.rule_id = rule_id
        self.pattern = pattern
        self.replacement = replacement
        self.flags = flags

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


def _flag_bits(flag_names: Iterable[str]) -> int:
    bits = 0
    for name in (f.strip().upper() for f in flag_names):
        if not name:
            continue
        if name in ("I", "IGNORECASE"):
            bits |= re.IGNORECASE
        elif name in ("M", "MULTILINE"):
            bits |= re.MULTILINE
        elif name in ("S", "DOTALL"):
            bits |= re.DOTALL
        elif name in ("U", "UNICODE"):
            bits |= re.UNICODE
        elif name in ("X", "VERBOSE"):
            bits |= re.VERBOSE
    return bits


def get_redact_rules() -> List[RedactRule]:
    """Return compiled redact rules from merged policy packs."""

    merged: Dict[str, Any] = {}
    if _policy and hasattr(_policy, "get"):
        try:
            merged = _policy.get()
        except Exception:
            merged = {}

    rules = (((merged or {}).get("rules")) or {}).get("redact") or []
    out: List[RedactRule] = []
    for r in rules:
        rid = str(r.get("id") or r.get("name") or f"rule-{len(out) + 1}")
        pat = str(r.get("pattern") or "")
        if not pat:
            continue
        repl = str(r.get("replacement") or "█")
        flgs = r.get("flags") or []
        bits = _flag_bits(flgs if isinstance(flgs, list) else [flgs])
        out.append(RedactRule(rid, pat, repl, bits))
    return out
