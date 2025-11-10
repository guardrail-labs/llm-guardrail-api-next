from __future__ import annotations

from app.services.detectors import html_hidden as mod


def test_html_hidden_detector_finds_style_hidden():
    html = """
    <div>
      <p style="display:none">secret line here</p>
      <p>visible</p>
    </div>
    """
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "style_hidden" in res["reasons"]
    assert any("secret line here" in s for s in res["samples"])


def test_html_white_on_white():
    html = """
    <span style="color:#fff;background:#ffffff">top secret</span>
    """
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "white_on_white" in res["reasons"]
    assert any("top secret" in s for s in res["samples"])


def test_html_hidden_attr_and_class():
    html = """
    <div hidden>do not show</div>
    <div class="sr-only">screen-reader only secret</div>
    """
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "attr_hidden" in res["reasons"] or "class_hidden" in res["reasons"]
    assert any("do not show" in s or "screen-reader only secret" in s for s in res["samples"])


def test_html_text_indent_offscreen():
    html = '<p style="text-indent:-9999px">hidden away</p>'
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "style_hidden" in res["reasons"]
    assert any("hidden away" in s for s in res["samples"])


def test_html_line_height_zero():
    html = '<p style="line-height:0">tiny line</p>'
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "style_hidden" in res["reasons"]
    assert any("tiny line" in s for s in res["samples"])


def test_html_z_index_negative_absolute():
    html = '<p style="position:absolute;z-index:-1">behind</p>'
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "style_hidden" in res["reasons"]
    assert any("behind" in s for s in res["samples"])


def test_html_css_var_white_on_white():
    html = '<span style="--fg:#fff;color:var(--fg);background:#ffffff">vars</span>'
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "white_on_white" in res["reasons"]
    assert any("vars" in s for s in res["samples"])
