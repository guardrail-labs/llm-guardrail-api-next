from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import List, Optional, TypedDict

import yaml

# File lives at repo_root/config/bindings.yaml
# app/services -> app -> repo_root
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _REPO_ROOT / "config"
_CONFIG_PATH = _CONFIG_DIR / "bindings.yaml"

_LOCK = RLock()


class Binding(TypedDict):
    tenant: str
    bot: str
    rules_path: str


@dataclass(frozen=True)
class BindingsDoc:
    version: str
    bindings: List[Binding]


def _ensure_dirs() -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not _CONFIG_PATH.exists():
        _CONFIG_PATH.write_text(
            yaml.safe_dump({"version": "1", "bindings": []}), encoding="utf-8"
        )


def load_bindings() -> BindingsDoc:
    with _LOCK:
        _ensure_dirs()
        data = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
        version = str(data.get("version", "1"))
        raw = data.get("bindings") or []
        bindings: List[Binding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            tenant = str(item.get("tenant", "")).strip() or "default"
            bot = str(item.get("bot", "")).strip() or "default"
            path = str(item.get("rules_path", "")).strip()
            if path:
                bindings.append({"tenant": tenant, "bot": bot, "rules_path": path})
        return BindingsDoc(version=version, bindings=bindings)


def save_bindings(bindings: List[Binding], version: Optional[str] = None) -> BindingsDoc:
    with _LOCK:
        _ensure_dirs()
        doc = {"version": str(version or "1"), "bindings": list(bindings)}
        _CONFIG_PATH.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        return load_bindings()


def upsert_binding(tenant: str, bot: str, rules_path: str) -> BindingsDoc:
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    bindings = load_bindings().bindings
    # replace if exists
    updated: List[Binding] = []
    found = False
    for b in bindings:
        if b["tenant"] == tenant and b["bot"] == bot:
            updated.append({"tenant": tenant, "bot": bot, "rules_path": rules_path})
            found = True
        else:
            updated.append(b)
    if not found:
        updated.append({"tenant": tenant, "bot": bot, "rules_path": rules_path})
    return save_bindings(updated)


def delete_binding(tenant: Optional[str] = None, bot: Optional[str] = None) -> BindingsDoc:
    bindings = load_bindings().bindings
    if not tenant and not bot:
        # clear all
        return save_bindings([])
    tenant = (tenant or "").strip()
    bot = (bot or "").strip()
    kept: List[Binding] = []
    for b in bindings:
        if tenant and bot:
            if b["tenant"] == tenant and b["bot"] == bot:
                continue
        elif tenant:
            if b["tenant"] == tenant:
                continue
        elif bot:
            if b["bot"] == bot:
                continue
        kept.append(b)
    return save_bindings(kept)


def resolve_rules_path(tenant: str, bot: str) -> Optional[str]:
    """
    Exact match first; then wildcard '*' for tenant and/or bot.
    Return first matching rules_path, else None.
    """
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    doc = load_bindings()
    # exact
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == bot:
            return b["rules_path"]
    # tenant + wildcard bot
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == "*":
            return b["rules_path"]
    # wildcard tenant + bot
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == bot:
            return b["rules_path"]
    # global wildcard
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == "*":
            return b["rules_path"]
    return None
