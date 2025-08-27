from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict

import yaml

from app.config import Settings


@dataclass
class PolicyBlob:
    rules: dict
    version: str
    path: str
    mtime: float


_cache: Dict[str, PolicyBlob] = {}


def _default_path() -> str:
    return str(Path(__file__).resolve().parent.parent / "policy" / "rules.yaml")


def _resolve_path() -> str:
    s = Settings()
    path = (s.POLICY_RULES_PATH or "").strip()
    return path or _default_path()


def _load_from_disk(path: str) -> PolicyBlob:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    rules = yaml.safe_load(text) or {}
    mtime = p.stat().st_mtime
    # Prefer explicit version; otherwise use mtime as a monotonic-ish fallback
    version = str(rules.get("version", int(mtime)))
    return PolicyBlob(rules=rules, version=version, path=str(p), mtime=mtime)


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

