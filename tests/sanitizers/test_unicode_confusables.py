from app.sanitizers.unicode_sanitizer import detect_unicode_anomalies, normalize_nfkc


def _extract_types(text: str) -> set[str]:
    return {finding["type"] for finding in detect_unicode_anomalies(text)}


def test_detect_zero_width() -> None:
    text = "pa\u200bss"
    findings = detect_unicode_anomalies(text)
    assert any(f["type"] == "zero_width" and f["span"] == (2, 3) for f in findings)
    assert any(f["codepoint"] == "U+200B" for f in findings)


def test_detect_bidi() -> None:
    text = "hello\u202eworld"
    findings = detect_unicode_anomalies(text)
    assert any(f["type"] == "bidi_control" and f["codepoint"] == "U+202E" for f in findings)


def test_detect_fullwidth() -> None:
    text = "ＡＢＣ"
    findings = detect_unicode_anomalies(text)
    assert all(f["type"] == "fullwidth" for f in findings)
    assert {f["codepoint"] for f in findings} == {"U+FF21", "U+FF22", "U+FF23"}


def test_detect_greek_cyrillic() -> None:
    text = "latinΑβД"
    types = _extract_types(text)
    assert "greek" in types
    assert "cyrillic" in types


def test_nfkc_idempotent() -> None:
    text = "hello café"
    assert normalize_nfkc(text) == text
