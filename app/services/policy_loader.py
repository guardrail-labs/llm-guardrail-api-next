from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Pattern, Tuple

import yaml

from app.config import Settings


@dataclass
class PolicyBlob:
    rules: dict
    version: str
    path: str
    mtime: float
    # List of (rule_id, compiled_pattern)
    deny_compiled: List[Tuple[str, Pattern[str]]]


_cache: Dict[str, PolicyBlob] = {}


def _default_path() -> str:
    return str(Path(__file__).resolve().parent.parent / "policy" / "rules.yaml")


def _resolve_path() -> str:
    s = Settings()
    path = (s.POLICY_RULES_PATH or "").strip()
    return path or _default_path()


def _flag_bits(flags: List[str] | None) -> int:
    """Translate YAML flags like ['i','m','s'] into re flags."""
    if not flags:
        return 0
    mapping = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    bits = 0
    for f in flags:
        if f in mapping:
            bits |= mapping[f]
    return bits


def _compile_deny(rules: dict) -> List[Tuple[str, Pattern[str]]]:
    out: List[Tuple[str, Pattern[str]]] = []
    deny = rules.get("deny", [])
    if not isinstance(deny, list):
        return out
    for item in deny:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("id", "")).strip() or "unnamed"
        pat = str(item.get("pattern", ""))
        flags = _flag_bits(item.get("flags"))
        try:
            cp = re.compile(pat, flags)
            out.append((rid, cp))
        except re.error:
            # Skip invalid regex; policy authors can fix in file
            continue
    return out


def _load_from_disk(path: str) -> PolicyBlob:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    rules = yaml.safe_load(text) or {}
    mtime = p.stat().st_mtime
    version = str(rules.get("version", int(mtime)))
    deny_compiled = _compile_deny(rules)
    return PolicyBlob(
        rules=rules,
        version=version,
        path=str(p),
        mtime=mtime,
        deny_compiled=deny_compiled,
    )


def get_policy() -> PolicyBlob:
    """Return the current policy; refresh if POLICY_AUTORELOAD and mtime changed."""
    path = _resolve_path()
    s = Settings()

    blob = _cache.get(path)
    if blob is None:
        blob = _load_from_disk(path)
        _cache[path] = blob
        return blob

    if s.POLICY_AUTORELOAD:
        try:
            mtime = Path(path).stat().st_mtime
        except FileNotFoundError:
            return blob
        if mtime != blob.mtime:
            blob = _load_from_disk(path)
            _cache[path] = blob

    return blob


def reload_now() -> PolicyBlob:
    """Force a reload regardless of POLICY_AUTORELOAD."""
    path = _resolve_path()
    blob = _load_from_disk(path)
    _cache[path] = blob
    return blob

