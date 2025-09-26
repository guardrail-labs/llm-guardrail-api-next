from app.sanitizers.encoding_sanitizer import decode_string_once


def test_decode_base64_simple():
    # "hello" -> aGVsbG8=
    s, stats = decode_string_once("aGVsbG8=")
    assert s == "hello"
    assert stats["decoded_base64"] == 1
    assert stats["changed"] == 1


def test_decode_hex_simple():
    # "test" -> 74657374
    s, stats = decode_string_once("74657374")
    assert s == "test"
    assert stats["decoded_hex"] == 1
    assert stats["changed"] == 1


def test_decode_url_simple():
    s, stats = decode_string_once("prompt%20injection%3A%20do%20x")
    assert s == "prompt injection: do x"
    assert stats["decoded_url"] == 1
    assert stats["changed"] == 1


def test_no_decode_on_short_or_invalid():
    # Too short for base64/hex
    s, stats = decode_string_once("abc")
    assert s == "abc"
    assert stats["changed"] == 0
