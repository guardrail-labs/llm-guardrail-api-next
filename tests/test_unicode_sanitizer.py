from __future__ import annotations

from app.sanitizers.unicode import (
    contains_raw_bidi,
    contains_zero_width,
    sanitize_unicode,
)


def test_nfkc_normalization_applied() -> None:
    src = "Value ①"
    out = sanitize_unicode(src)
    assert "①" not in out
    assert "1" in out


def test_zero_width_characters_removed() -> None:
    src = "A\u200bB\u200dC"
    out = sanitize_unicode(src)
    assert out == "ABC"
    assert not contains_zero_width(out)


def test_bidi_controls_escaped() -> None:
    src = "a\u202ebc"
    out = sanitize_unicode(src)
    assert not contains_raw_bidi(out)
    assert "\\u202e" in out
    for ch in "abc":
        assert ch in out


def test_compound_attack_string() -> None:
    src = "𝔘\u200b𝔫\u2066\u202eï\u200d\u200f"
    out = sanitize_unicode(src)
    assert "Un" in out
    assert not contains_zero_width(out)
    assert not contains_raw_bidi(out)
    assert any(
        escape in out for escape in ("\\u202e", "\\u2066", "\\u200f")
    )


def test_bom_and_soft_hyphen_removed() -> None:
    src = "\ufeffA\u00adB"
    out = sanitize_unicode(src)
    assert out == "AB"
