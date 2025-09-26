from app.sanitizers.unicode_emoji import analyze_emoji_sequences


def test_extracts_ascii_from_tag_sequence() -> None:
    # Build a TAG string for "secret"
    tag_bytes = [0xE0000 + ord(c) for c in "secret"]
    # Add CANCEL TAG to end
    tag_bytes.append(0xE007F)
    s = "".join(chr(cp) for cp in tag_bytes)
    revealed, st = analyze_emoji_sequences(s)
    assert revealed == "secret"
    assert st["tag_seq"] == 1
    assert st["tag_chars"] >= 6
    assert st["cancel_tags"] >= 1
    assert st["changed"] == 1


def test_counts_zwj_controls() -> None:
    s = "👨\u200d💻 dev"  # man technologist (ZWJ)
    revealed, st = analyze_emoji_sequences(s)
    assert revealed == "" or isinstance(revealed, str)
    assert st["zwj"] >= 1
    assert st["controls_inside"] >= 1
