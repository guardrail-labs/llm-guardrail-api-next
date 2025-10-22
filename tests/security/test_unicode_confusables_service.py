from __future__ import annotations

from app.services.unicode_confusables import analyze_text, sanitize_text


def test_detects_confusable_pairs_and_mixed_scripts() -> None:
    text = "Pаypal"  # Cyrillic 'a' in position 2
    rep = analyze_text(text)
    assert rep.has_non_ascii is True
    assert rep.has_mixed_scripts is True
    assert len(rep.confusable_pairs) >= 1


def test_normalize_mode_changes_when_needed() -> None:
    changed, rep = sanitize_text("e\u0301", mode="normalize", form="NFC")
    # NFC composes 'e' + acute to 'é'
    assert changed == "é"
    assert rep is not None
    assert rep.normalized_changed is True


def test_strip_replaces_known_confusables() -> None:
    text = "Рython"  # Cyrillic 'Rho' lookalike 'P'
    out, _ = sanitize_text(text, mode="strip")
    assert "Python" in out


def test_block_mode_signals_block_on_mixed_or_pairs() -> None:
    text = "Domaіn"  # Cyrillic small byelorussian i
    out, rep = sanitize_text(text, mode="block")
    assert out == text
    assert rep is not None
    assert rep.has_mixed_scripts or rep.confusable_pairs
