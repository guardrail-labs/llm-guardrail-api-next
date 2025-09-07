from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.telemetry import metrics as m

client = TestClient(app)


def test_pdf_hidden_hex_is_exposed_and_redacted():
    # Hex-encoded "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ" shown via Tj,
    # with a white non-stroking color (heuristic match).
    secret = b"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    hex_text = b"".join(f"{b:02X}".encode("ascii") for b in secret)

    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"stream\n"
        b"1 1 1 rg\n"              # white non-stroking fill
        b"<" + hex_text + b"> Tj\n"
        b"endstream\n%%EOF\n"
    )

    files = [("files", ("hidden.pdf", pdf, "application/pdf"))]
    # Avoid Prometheus label conflicts in test environment.
    m.inc_redaction = lambda *a, **k: None
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    body = r.json()

    # API still allows; redactions are applied in transformed text.
    assert body["action"] == "allow"
    assert "[HIDDEN_TEXT_DETECTED" in body["text"]
    assert "[REDACTED:OPENAI_KEY]" in body["text"]
