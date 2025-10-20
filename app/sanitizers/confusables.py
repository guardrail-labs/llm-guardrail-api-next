from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Tuple

_ASCII_LETTER_DIGIT: Tuple[int, ...] = tuple(
    [
        *range(ord("0"), ord("9") + 1),
        *range(ord("A"), ord("Z") + 1),
        *range(ord("a"), ord("z") + 1),
    ]
)


def _is_ascii_ld(ch: str) -> bool:
    return len(ch) == 1 and ord(ch) in _ASCII_LETTER_DIGIT


def _looks_ascii_after_nfkd(ch: str) -> bool:
    """
    Heuristic: characters that decompose to ASCII letter/digit only.
    Avoids third-party libs while catching common homoglyphs.
    """
    decomp = unicodedata.normalize("NFKD", ch)
    if not decomp:
        return False
    for c in decomp:
        if unicodedata.combining(c):
            continue
        if not _is_ascii_ld(c):
            return False
    return any(_is_ascii_ld(c) and not unicodedata.combining(c) for c in decomp)


@dataclass(frozen=True)
class ConfusableReport:
    total_ld: int
    confusable_count: int
    ratio: float


def analyze_confusables(text: str) -> ConfusableReport:
    total = 0
    hits = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("L") or cat.startswith("N"):
            total += 1
            if not _is_ascii_ld(ch) and _looks_ascii_after_nfkd(ch):
                hits += 1
    ratio = (hits / total) if total else 0.0
    return ConfusableReport(total_ld=total, confusable_count=hits, ratio=ratio)


def escape_confusables(text: str) -> str:
    """
    Replace confusable chars with \\uXXXX escapes, preserving length semantics.
    """
    out: list[str] = []
    for ch in text:
        if not _is_ascii_ld(ch) and _looks_ascii_after_nfkd(ch):
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)
