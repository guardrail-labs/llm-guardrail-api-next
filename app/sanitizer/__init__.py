"""Reusable sanitizer helpers for ingress guards."""

from __future__ import annotations

import unicodedata
from typing import Any, Dict, Iterable

from .confusables_data import (
    CONFUSABLES_MAP,
    SUSPICIOUS_SCRIPTS,
    ZERO_WIDTH_CHARACTERS,
)


def normalize_text(value: str) -> str:
    """Normalize text to NFC and strip zero-width characters."""
    if not value:
        return ""
    normalized = unicodedata.normalize("NFC", value)
    cleaned = "".join(ch for ch in normalized if ch not in ZERO_WIDTH_CHARACTERS)
    return cleaned


def _script_of(char: str) -> str | None:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    for script_name, label in SUSPICIOUS_SCRIPTS.items():
        if script_name in name:
            return label
    if "LATIN" in name or "DIGIT" in name:
        return "latin"
    return None


def detect_confusables(value: str) -> list[str]:
    """Return a list of confusable character descriptions present in ``value``."""
    findings: list[str] = []
    seen: set[str] = set()
    scripts: set[str] = set()

    for char in value:
        script = _script_of(char)
        if script:
            scripts.add(script)
        if char in CONFUSABLES_MAP and char not in seen:
            seen.add(char)
            codepoint = f"U+{ord(char):04X}"
            display = CONFUSABLES_MAP[char]
            name = unicodedata.name(char, "UNKNOWN")
            findings.append(f"{codepoint} {name}→{display}")

    if len(scripts) > 1 and "latin" in scripts:
        # Highlight mixed-script usage that can be used for spoofing attacks.
        # We prefix with MIXED-SCRIPT so callers can display it distinctively.
        other_scripts = sorted(s for s in scripts if s != "latin")
        if other_scripts:
            findings.append("MIXED-SCRIPT:" + ",".join(other_scripts))

    return findings


def _sanitize_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in mapping.items():
        sanitized[key] = sanitize_input(value)
    return sanitized


def _sanitize_iterable(items: Iterable[Any]) -> list[Any]:
    return [sanitize_input(item) for item in items]


def sanitize_input(payload: Dict[str, Any] | str | list[Any]) -> Dict[str, Any] | str | list[Any]:
    """Sanitize inbound payloads by normalizing contained strings."""
    if isinstance(payload, str):
        return normalize_text(payload)
    if isinstance(payload, dict):
        return _sanitize_mapping(payload)
    if isinstance(payload, (list, tuple, set)):
        return _sanitize_iterable(payload)
    return payload


__all__ = ["normalize_text", "detect_confusables", "sanitize_input"]
