from __future__ import annotations

from app.services.detectors import html_hidden as mod

def test_html_hidden_detector_finds_style_hidden():
    html = '''
    <div>
      <p style="display:none">secret line here</p>
      <p>visible</p>
    </div>
    '''
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "css:display-none" in res["reasons"]
    assert any("secret line here" in s for s in res["samples"])

def test_html_white_on_white():
    html = '''
    <span style="color:#fff;background:#ffffff">top secret</span>
    '''
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "css:low-contrast" in res["reasons"]
    assert any("top secret" in s for s in res["samples"])

def test_html_hidden_attr_and_class():
    html = '''
    <div hidden>do not show</div>
    <div aria-hidden="true">screen-reader only secret</div>
    '''
    res = mod.detect_hidden_text(html)
    assert res["found"] is True
    assert "attr:hidden" in res["reasons"] or "attr:aria-hidden" in res["reasons"]
    assert any("do not show" in s or "screen-reader only secret" in s for s in res["samples"])
