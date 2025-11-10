from app.sanitizers.metadata import sanitize_filename, sanitize_header_value


def test_sanitize_header_basic():
    out, st = sanitize_header_value("ok\u200bval\u202e")
    assert out == "okval"
    assert st["zero_width_removed"] >= 1 or st["bidi_controls_removed"] >= 1


def test_filename_strips_paths_and_badchars():
    name, st = sanitize_filename("../bad\\path/..//evil..txt")
    assert name.endswith("evil..txt".rstrip(" .")) or name.endswith("evil.txt")
    assert "/" not in name and "\\" not in name
    assert st["changed"] == 1


def test_filename_empty_becomes_file():
    name, _ = sanitize_filename("..")
    assert name == "file"
