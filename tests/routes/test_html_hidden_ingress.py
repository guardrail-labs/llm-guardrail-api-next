from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.telemetry import metrics as m

client = TestClient(app)


def test_multipart_html_hidden_exposed_and_redacted():
    m.inc_redaction = lambda *a, **k: None
    # Hidden HTML that also contains an API-like secret to ensure redaction fires.
    html = """
    <html>
      <body>
        <div style="display:none">sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
        <p>hello</p>
      </body>
    </html>
    """.encode("utf-8")

    files = [("files", ("hidden.html", html, "text/html"))]
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    body = r.json()

    # Allowed with transformed text showing the hidden detection block.
    assert body["action"] == "allow"
    txt = body["text"]
    assert "[HIDDEN_HTML_DETECTED:" in txt
    # secret should be redacted
    assert "[REDACTED:OPENAI_KEY]" in txt or "[REDACTED" in txt
