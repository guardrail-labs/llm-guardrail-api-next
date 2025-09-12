from __future__ import annotations

from app.services.detect.hidden_text import detect_hidden_text_html


def test_html_detects_display_none() -> None:
    html = '<div><span style="display:none">secret</span></div>'
    out = detect_hidden_text_html(html)
    assert any(f.reason == "display:none" for f in out)


def test_html_detects_visibility_hidden() -> None:
    html = '<p style="visibility:hidden">hidden text</p>'
    out = detect_hidden_text_html(html)
    assert any(f.reason == "visibility:hidden" for f in out)


def test_html_detects_font_size_zero() -> None:
    html = '<p style="font-size:0px">invisible</p>'
    out = detect_hidden_text_html(html)
    assert any(f.reason == "font-size:0" for f in out)


def test_html_detects_color_equals_background() -> None:
    html = '<span style="color:#fff; background-color:#ffffff">camouflage</span>'
    out = detect_hidden_text_html(html)
    assert any(f.reason == "color==background-color" for f in out)


def test_html_detects_hidden_attrs() -> None:
    html = '<div hidden>h</div><div aria-hidden="true">x</div>'
    out = detect_hidden_text_html(html)
    reasons = {f.reason for f in out}
    assert "hidden-attr" in reasons
    assert "aria-hidden=true" in reasons
