from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.services.rulepacks import load_rulepack

Redaction = Tuple[re.Pattern[str], str]


@dataclass(frozen=True)
class CompiledRulepacks:
    egress_redactions: Tuple[Redaction, ...]
    ingress_block_regexes: Tuple[re.Pattern[str], ...]
    names: Tuple[str, ...]


_CACHE: Optional[CompiledRulepacks] = None
_CACHE_KEY: Optional[Tuple[str, str, str]] = None  # (active, dir, versions-hashish)


def _get_env_active() -> Tuple[str, ...]:
    raw = (os.getenv("RULEPACKS_ACTIVE") or "").strip()
    if not raw:
        return tuple()
    return tuple(x.strip() for x in raw.split(",") if x.strip())


def _get_dir() -> str:
    return os.getenv("RULEPACKS_DIR", "rulepacks")


def _hashish(names: Tuple[str, ...]) -> str:
    # cheap marker; we can improve if rulepacks change while process runs
    return "|".join(names)


def _valid_pattern(p: str) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(p, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return None


def compile_active_rulepacks(force: bool = False) -> CompiledRulepacks:
    global _CACHE, _CACHE_KEY
    names = _get_env_active()
    rp_dir = _get_dir()
    key = (",".join(names), rp_dir, _hashish(names))
    if not force and _CACHE is not None and _CACHE_KEY == key:
        return _CACHE

    egress_redactions: List[Redaction] = []
    ingress_block_regexes: List[re.Pattern[str]] = []

    for name in names:
        data = load_rulepack(name)  # raises if missing
        controls = data.get("controls") or []
        for ctl in controls:
            phase = str(ctl.get("phase", "")).lower()
            action = str(ctl.get("action", "")).lower()
            typ = str(ctl.get("type", "")).lower()
            pattern = ctl.get("pattern")
            replacement = ctl.get("replacement", "[REDACTED]")

            if (
                phase == "egress"
                and action == "redact"
                and typ == "regex"
                and isinstance(pattern, str)
            ):
                c = _valid_pattern(pattern)
                if c:
                    egress_redactions.append((c, str(replacement)))
            if (
                phase == "ingress"
                and action in {"block", "deny"}
                and typ in {"regex", "substring"}
                and isinstance(pattern, str)
            ):
                if typ == "regex":
                    c = _valid_pattern(pattern)
                else:
                    c = _valid_pattern(re.escape(pattern))
                if c:
                    ingress_block_regexes.append(c)

    _CACHE = CompiledRulepacks(
        egress_redactions=tuple(egress_redactions),
        ingress_block_regexes=tuple(ingress_block_regexes),
        names=names,
    )
    _CACHE_KEY = key
    return _CACHE


def rulepacks_enabled() -> bool:
    return os.getenv("RULEPACKS_ENFORCE", "0") == "1"


def ingress_mode() -> str:
    return os.getenv("RULEPACKS_INGRESS_MODE", "clarify").lower()


def egress_mode() -> str:
    return os.getenv("RULEPACKS_EGRESS_MODE", "enforce").lower()


def ingress_should_block(text: str) -> Tuple[bool, List[str]]:
    """Return (should_block, matched_patterns)."""
    if not rulepacks_enabled():
        return False, []
    rs = compile_active_rulepacks()
    hits: List[str] = []
    for pat in rs.ingress_block_regexes:
        if pat.search(text):
            hits.append(pat.pattern)
    if not hits:
        return False, []
    return True, hits


def egress_redactions() -> Tuple[Redaction, ...]:
    if not rulepacks_enabled():
        return tuple()
    rs = compile_active_rulepacks()
    return rs.egress_redactions
