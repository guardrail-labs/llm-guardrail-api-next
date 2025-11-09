from __future__ import annotations

from app.sanitizer import detect_confusables, normalize_text, sanitize_input


def test_normalize_text_strips_zero_width_and_normalizes():
    raw = "Cafe\u0301"  # composed form with combining accent
    normalized = normalize_text(raw + "\u200b")
    assert normalized == "Café"


def test_detect_confusables_reports_mixed_scripts():
    text = "p\u0430ypal"  # replace first "a" with Cyrillic a
    findings = detect_confusables(text)
    assert any(f.startswith("U+") for f in findings)
    assert any(item.startswith("MIXED-SCRIPT") for item in findings)


def test_sanitize_input_handles_nested_structures():
    payload = {"text": "He\u200bllo", "list": ["A\u2009", {"inner": "\u0430"}]}
    sanitized = sanitize_input(payload)
    assert sanitized["text"] == "Hello"
    # Thin space is preserved; sanitizer focuses on zero-width characters.
    assert sanitized["list"][0] == "A\u2009"
    assert sanitized["list"][1]["inner"] == "\u0430"
