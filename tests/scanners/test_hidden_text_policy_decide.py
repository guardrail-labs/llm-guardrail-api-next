from importlib import reload

import app.services.scanners.hidden_text.policy as pol
import app.settings as settings


def test_policy_deny_when_reason_matches(monkeypatch):
    monkeypatch.setenv("HIDDEN_TEXT_POLICY", "1")
    monkeypatch.setenv("HIDDEN_TEXT_DENY_REASONS", "docx_vanish")
    monkeypatch.setenv("HIDDEN_TEXT_CLARIFY_REASONS", "")
    reload(settings)
    reload(pol)
    action, matched = pol.decide_for_hidden_reasons("docx", ["docx_vanish"])
    assert action == "deny"
    assert matched == ["docx_vanish"]


def test_policy_clarify_threshold(monkeypatch):
    monkeypatch.setenv("HIDDEN_TEXT_POLICY", "1")
    monkeypatch.setenv("HIDDEN_TEXT_MIN_MATCH", "2")
    monkeypatch.setenv("HIDDEN_TEXT_DENY_REASONS", "")
    monkeypatch.setenv("HIDDEN_TEXT_CLARIFY_REASONS", "style_hidden,zero_width_chars")
    reload(settings)
    reload(pol)
    action, matched = pol.decide_for_hidden_reasons(
        "html", ["style_hidden", "zero_width_chars"]
    )
    assert action == "clarify"
    assert set(matched) == {"style_hidden", "zero_width_chars"}
