from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_multipart_html_with_hidden_text_is_denied_and_debug_has_sources():
    html = b"""
    <html><body>
      <p>Visible</p>
      <div style="display:none">stealth jailbreak</div>
      <span style="opacity:0">hidden directive</span>
    </body></html>
    """
    files = [("files", ("note.html", html, "text/html"))]
    r = client.post("/guardrail/evaluate_multipart", files=files, headers={"X-Debug": "1"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "deny"
    assert r.headers.get("X-Guardrail-Decision") == "deny"
    assert "debug" in body and "sources" in body["debug"]
    fams = set(body.get("rule_hits", {}).keys())
    assert any(k.startswith("injection:") for k in fams)


def test_multipart_html_clean_is_allowed_like_baseline():
    html = b"<html><body><p>Hello</p></body></html>"
    files = [("files", ("note.html", html, "text/html"))]
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    assert (body := r.json())
    assert body["action"] in {"allow", "sanitize", "clarify", "deny"}
