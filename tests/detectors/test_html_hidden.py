from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_html_hidden_injection_is_surfaced_and_redacted():
    html = b'''<html><body>
    <div style="display:none">sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
    <p>hello</p>
    </body></html>'''
    files = [("files", ("page.html", html, "text/html"))]
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "[HIDDEN_HTML_DETECTED:" in body["text"]
    assert "[REDACTED:OPENAI_KEY]" in body["text"]
