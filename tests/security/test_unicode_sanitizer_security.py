from app.security.unicode_sanitizer import (
    UnicodeSanitizerCfg,
    normalize_nfkc,
    sanitize_unicode,
    scan_unicode_threats,
)


def test_mixed_script_detects_and_blocks() -> None:
    text = "pаypal"  # second character is Cyrillic "а"
    normalized = normalize_nfkc(text)
    report = scan_unicode_threats(normalized)
    assert report["mixed_script_tokens"] > 0
    assert "mixed_script" in report["reasons"]

    result = sanitize_unicode(text, UnicodeSanitizerCfg(), report=report)
    assert result.should_block
    assert "mixed_script" in result.block_reasons


def test_bidi_control_triggers_block() -> None:
    text = "abc\u202etxt"
    normalized = normalize_nfkc(text)
    report = scan_unicode_threats(normalized)
    assert report["has_bidi"] is True
    assert "bidi_control" in report["reasons"]

    result = sanitize_unicode(text, UnicodeSanitizerCfg(), report=report)
    assert result.should_block
    assert "bidi_control" in result.block_reasons


def test_zero_width_joiner_blocks() -> None:
    text = "a\u200db"
    normalized = normalize_nfkc(text)
    report = scan_unicode_threats(normalized)
    assert report["has_zw"] is True
    assert "zero_width" in report["reasons"]

    result = sanitize_unicode(text, UnicodeSanitizerCfg(), report=report)
    assert result.should_block
    assert "zero_width" in result.block_reasons


def test_emoji_heavy_warns_only() -> None:
    text = "😀🔥🚀✨✨ text"
    normalized = normalize_nfkc(text)
    report = scan_unicode_threats(normalized, emoji_warn_ratio=0.5)
    assert "emoji_heavy" in report["reasons"]

    result = sanitize_unicode(text, UnicodeSanitizerCfg(), report=report)
    assert not result.should_block
    assert "emoji_heavy" in result.report["reasons"]
    assert result.report["suspicious"] is False


def test_plain_text_idempotent() -> None:
    text = "Hello world"
    normalized = normalize_nfkc(text)
    assert normalized == text
    report = scan_unicode_threats(normalized)
    assert report["reasons"] == []

    result = sanitize_unicode(text, UnicodeSanitizerCfg(), report=report)
    assert not result.should_block
    assert result.report["reasons"] == []
    assert result.text == text
