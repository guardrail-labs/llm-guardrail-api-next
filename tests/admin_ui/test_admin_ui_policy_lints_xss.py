from __future__ import annotations

from typing import Any, Dict, List

from app.routes.admin_ui import templates


def _render_policy_with_lints(lints: List[Dict[str, Any]]) -> str:
    template = templates.env.get_template("policy.html")
    context = {
        "request": object(),
        "csrf_token": "csrf-123",
        "version": "v-test",
        "packs": ["pack-a"],
        "lints": lints,
    }
    return template.render(context)


def test_position_metadata_escapes_malicious_values() -> None:
    html = _render_policy_with_lints(
        [
            {
                "severity": "error",
                "message": "Injected",
                "line": '"><script>window.__xss=1</script>',
                "column": "7",
                "offset": "9",
            }
        ]
    )

    assert "window.__xss=1</script>" not in html
    assert "Position:</span> line 0, col 7, offset 9" in html


def test_position_metadata_renders_numeric_values() -> None:
    html = _render_policy_with_lints(
        [
            {
                "severity": "warn",
                "message": "Regular lint",
                "line": 12,
                "column": 7,
                "offset": 3,
            }
        ]
    )

    assert "Position:</span> line 12, col 7, offset 3" in html


def test_meta_join_does_not_render_injected_html() -> None:
    html = _render_policy_with_lints(
        [
            {
                "severity": "info",
                "message": "Sanitized path",
                "path": "$.<b>bold</b>",
                "line": 1,
            }
        ]
    )

    assert "<b>bold</b>" not in html
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
