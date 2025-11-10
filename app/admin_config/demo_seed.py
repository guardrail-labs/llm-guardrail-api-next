"""Utilities to seed demo bindings on startup."""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from app import config
from app.services import config_store
from app.services.bindings.utils import (
    compute_version_for_path,
    propagate_bindings,
    read_policy_version,
)

_DEMO_BINDINGS: Tuple[Tuple[str, str, str], ...] = (
    ("demo", "site", "pii_redact"),
    ("demo", "site", "secrets_redact"),
)


def _serialize(bindings: Iterable[config_store.Binding]) -> List[Dict[str, str]]:
    serialized: List[Dict[str, str]] = []
    for binding in bindings:
        rules_path = binding["rules_path"]
        version = compute_version_for_path(rules_path)
        policy_version = read_policy_version(rules_path) or version
        serialized.append(
            {
                "tenant": binding["tenant"],
                "bot": binding["bot"],
                "rules_path": rules_path,
                "version": version,
                "policy_version": policy_version,
            }
        )
    return serialized


def seed_demo_defaults() -> None:
    """Ensure demo bindings include the default redaction packs when enabled."""

    try:
        settings = config.get_settings()
        if not getattr(settings, "DEMO_DEFAULT_BINDINGS", False):
            return
    except Exception:
        return

    try:
        doc = config_store.load_bindings()
    except Exception:
        return

    bindings = list(doc.bindings)
    updated = False
    for tenant, bot, pack in _DEMO_BINDINGS:
        if any(
            b["tenant"] == tenant and b["bot"] == bot and b["rules_path"] == pack for b in bindings
        ):
            continue
        bindings.append({"tenant": tenant, "bot": bot, "rules_path": pack})
        updated = True

    if not updated:
        return

    try:
        updated_doc = config_store.save_bindings(bindings)
    except Exception:
        return

    try:
        payload = _serialize(updated_doc.bindings)
        propagate_bindings(payload)
    except Exception:
        pass
