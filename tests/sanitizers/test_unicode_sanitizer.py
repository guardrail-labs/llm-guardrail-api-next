from app.sanitizers.unicode_sanitizer import sanitize_payload, sanitize_text


def test_sanitize_text_removes_zero_width_and_bidi():
    s = "pa\u200bss\u202eword"  # "pa<ZWSP>ss<RLO>word"
    out, stats = sanitize_text(s)
    assert out == "password"
    assert stats["zero_width_removed"] >= 1
    assert stats["bidi_controls_removed"] >= 1
    assert stats["changed"] == 1


def test_confusables_basic_mapping():
    # Cyrillic 'а' (U+0430) in 'pаypal' should map to ASCII 'a'
    s = "p\u0430ypal"
    out, stats = sanitize_text(s)
    assert out == "paypal"
    assert stats["confusables_mapped"] >= 1


def test_payload_recursive_sanitization():
    data = {
        "ke\u200by": "v\u200bal",
        "list": ["\u202ehide", "ok"],
        "nested": {"\u0430uth": "gr\u0435at"},  # Cyrillic a/e
    }
    out, stats = sanitize_payload(data)
    assert "key" in out and out["key"] == "val"
    assert out["list"][0] == "hide"
    assert out["nested"]["auth"] == "great"
    assert stats["strings_seen"] >= 1
    assert (
        stats["zero_width_removed"] + stats["bidi_controls_removed"] + stats["confusables_mapped"]
    ) >= 1
