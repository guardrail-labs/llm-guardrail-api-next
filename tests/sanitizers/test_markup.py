from app.sanitizers.markup import looks_like_markup, strip_markup_to_text


def test_looks_like_markup_detects_html():
    assert looks_like_markup("<p>Hello</p>") is True
    assert looks_like_markup("no tags here") is False


def test_strip_basic_html():
    out, st = strip_markup_to_text("<b>He &amp; she</b>")
    assert out == "He & she"
    assert st["changed"] == 1


def test_strip_script_style_svg_foreign():
    html = "<div>ok</div><script>alert(1)</script><style>p{}</style>"
    out, st = strip_markup_to_text(html)
    assert "alert" not in out
    assert st["scripts_removed"] >= 1
    assert st["styles_removed"] >= 1


def test_strip_svg_like():
    svg = '<svg><text>hi</text><foreignObject><div>x</div></foreignObject></svg>'
    out, st = strip_markup_to_text(svg)
    assert "hi" in out
    assert st["foreign_removed"] >= 1
