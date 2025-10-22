"""Utilities for detecting and handling Unicode confusables.

The module provides a lightweight heuristic detector for mixed-script payloads and
common ASCII lookalikes. It avoids any heavy Unicode tables to keep the runtime
footprint minimal while still surfacing risky payloads that may trick downstream
authorization or routing logic.
"""

from __future__ import annotations

import unicodedata as _ud
from dataclasses import dataclass
from typing import Iterable, List, Literal, Optional, Set, Tuple, cast

# Minimal script tags for mixed-script heuristics (no external deps).
# Extend as needed; names are matched against unicodedata.name() prefixes.
_SCRIPT_TAGS = ("LATIN", "GREEK", "CYRILLIC", "HEBREW", "ARABIC", "DEVANAGARI")

NormalizationForm = Literal["NFC", "NFD", "NFKC", "NFKD"]
_NORMALIZATION_FORMS = {"NFC", "NFD", "NFKC", "NFKD"}


# Common ASCII lookalikes (subset; expand if needed).
# Source inspiration: Unicode confusables; kept tiny to avoid heavy tables.
_CONFUSABLES: Tuple[Tuple[str, str], ...] = (
    ("Α", "A"),  # Greek Alpha
    ("Β", "B"),  # Greek Beta
    ("Ε", "E"),
    ("Ζ", "Z"),
    ("Η", "H"),
    ("Ι", "I"),
    ("Κ", "K"),
    ("Μ", "M"),
    ("Ν", "N"),
    ("Ο", "O"),
    ("Ρ", "P"),
    ("Р", "P"),  # Cyrillic capital er
    ("Τ", "T"),
    ("Χ", "X"),
    ("Υ", "Y"),
    ("а", "a"),  # Cyrillic a
    ("е", "e"),  # Cyrillic e
    ("о", "o"),  # Cyrillic o
    ("р", "p"),  # Cyrillic r
    ("с", "c"),  # Cyrillic s
    ("х", "x"),  # Cyrillic x
)


@dataclass
class ConfusablesReport:
    """Summary of observed Unicode characteristics for a text payload."""

    has_non_ascii: bool
    has_mixed_scripts: bool
    confusable_pairs: List[Tuple[str, str]]
    norm_form: str
    normalized_changed: bool


def _char_script(ch: str) -> Optional[str]:
    try:
        name = _ud.name(ch)
    except ValueError:
        return None
    for tag in _SCRIPT_TAGS:
        if name.startswith(tag):
            return tag
    return None


def _scan_scripts(text: str) -> Set[str]:
    scripts: Set[str] = set()
    for ch in text:
        sc = _char_script(ch)
        if sc:
            scripts.add(sc)
    return scripts


def _scan_confusables(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not text:
        return out
    for foreign, ascii_ in _CONFUSABLES:
        if foreign in text:
            out.append((foreign, ascii_))
    return out


def _coerce_form(form: str) -> NormalizationForm:
    form_upper = form.upper()
    if form_upper in _NORMALIZATION_FORMS:
        return cast(NormalizationForm, form_upper)
    return "NFC"


def normalize_text(text: str, *, form: NormalizationForm = "NFC") -> str:
    """Return Unicode-normalized text, falling back to the original on failure."""

    try:
        return _ud.normalize(form, text)
    except Exception:
        return text


def analyze_text(text: str, *, form: NormalizationForm = "NFC") -> ConfusablesReport:
    """Analyse text for confusables, mixed scripts, and normalization changes."""

    has_non_ascii = any(ord(c) > 0x7F for c in text)
    scripts = _scan_scripts(text)
    mixed = len(scripts) > 1
    pairs = _scan_confusables(text)
    normed = normalize_text(text, form=form)
    changed = normed != text
    return ConfusablesReport(
        has_non_ascii=has_non_ascii,
        has_mixed_scripts=mixed,
        confusable_pairs=pairs,
        norm_form=form,
        normalized_changed=changed,
    )


def sanitize_text(
    text: str,
    *,
    mode: str = "normalize",  # normalize|strip|block|report-only
    form: str = "NFC",
) -> Tuple[str, Optional[ConfusablesReport]]:
    """Normalize or map confusables according to ``mode``."""

    norm_form = _coerce_form(form)
    rep = analyze_text(text, form=norm_form)
    mode_normalized = mode.lower()
    if mode_normalized == "report-only":
        return text, rep
    if mode_normalized == "block" and (
        rep.has_mixed_scripts or rep.confusable_pairs
    ):
        # Caller should raise or short-circuit based on this signal.
        return text, rep
    if mode_normalized == "strip":
        # Replace specific confusables with their ASCII lookalikes.
        out = text
        for foreign, ascii_ in _CONFUSABLES:
            out = out.replace(foreign, ascii_)
        # Also normalize to collapse combining marks safely.
        return normalize_text(out, form=norm_form), rep
    # Default: normalize (may still include non-ASCII but in canonical form).
    return normalize_text(text, form=norm_form), rep


def confusable_ascii_map() -> Iterable[Tuple[str, str]]:
    """Expose the confusable lookup table (useful for diagnostics/tests)."""

    return tuple(_CONFUSABLES)
