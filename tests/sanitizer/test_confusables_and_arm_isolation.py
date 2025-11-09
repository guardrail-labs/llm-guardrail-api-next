"""Tests for sanitizer helpers and arm isolation telemetry."""

from app.runtime import router
from app.sanitizer import detect_confusables, normalize_unicode, sanitize_input


def test_sanitize_input_removes_confusables() -> None:
    text = "pаypаl"  # contains Cyrillic a’s
    result = sanitize_input(text)
    assert result != text


def test_normalize_unicode_removes_zero_width() -> None:
    text = "he\u200bllo"
    assert normalize_unicode(text) == "hello"


def test_detect_confusables_list_nonempty() -> None:
    text = "gооgle"  # Cyrillic o
    confs = detect_confusables(text)
    assert isinstance(confs, list)
    assert all(isinstance(c, str) for c in confs)
    assert confs, "expected confusable characters to be detected"


def test_arm_failure_headers() -> None:
    router._ARM_FAILURES["ingress"] = 2
    router._ARM_FAILURES["egress"] = 1
    headers = router._decision_headers({"action": "allow"}, {"action": "allow"})
    assert headers["X-Guardrail-Arm-Failures-Ingress"] == "2"
    assert headers["X-Guardrail-Arm-Failures-Egress"] == "1"
