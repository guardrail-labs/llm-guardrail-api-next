"""Helpers for enforcing policy validation on reload/upload."""

from __future__ import annotations

import os
from typing import Any, Dict, Tuple

from app.services.policy_validate import validate_yaml_text


def _mode() -> str:
    """Return the configured enforcement mode (``warn`` or ``block``)."""

    val = (os.getenv("POLICY_VALIDATE_ENFORCE") or "warn").strip().lower()
    return "block" if val == "block" else "warn"


def validate_text_for_reload(yaml_text: str) -> Tuple[bool, Dict[str, Any]]:
    """Validate ``yaml_text`` and decide whether to allow applying the policy."""

    result = validate_yaml_text(yaml_text)
    has_error = any(i.get("severity") == "error" for i in result.get("issues", []))
    mode = _mode()
    allow = not (mode == "block" and has_error)
    enriched = {**result, "enforcement_mode": mode}
    return allow, enriched


__all__ = ["validate_text_for_reload"]
