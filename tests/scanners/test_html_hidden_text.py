from app.services.scanners.hidden_text.html import scan_html_for_hidden


def test_html_detects_style_hidden():
    html = '<div style="display:none">secret</div>'
    assert "style_hidden" in scan_html_for_hidden(html)


def test_html_detects_attr_hidden_and_zero_width():
    html = "<span hidden>h</span>\u200b"
    out = scan_html_for_hidden(html)
    assert "attr_hidden" in out
    assert "zero_width_chars" in out
