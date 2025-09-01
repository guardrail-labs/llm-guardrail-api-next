from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_multipart_pdf_with_secret_is_redacted():
    # Fake minimal PDF with embedded secret-like string
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"stream\n"
        b"Here sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ appears in content.\n"
        b"endstream\n%%EOF\n"
    )
    files = [
        ("files", ("test.pdf", pdf_bytes, "application/pdf")),
    ]
    r = client.post(
        "/guardrail/evaluate_multipart",
        files=files,
        data={"text": "hello"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "[REDACTED:OPENAI_KEY]" in body["text"]
    assert "secrets:*" in (body.get("rule_hits") or [])


def test_multipart_text_file_with_pii_is_redacted_and_debug_sources():
    txt_bytes = b"reach me at alice@example.com or 555-111-2222"
    files = [
        ("files", ("note.txt", txt_bytes, "text/plain")),
    ]
    r = client.post(
        "/guardrail/evaluate_multipart",
        files=files,
        headers={"X-Debug": "1"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    # Redactions applied
    assert "[REDACTED:EMAIL]" in body["text"]
    assert "[REDACTED:PHONE]" in body["text"]
    assert "pi:*" in (body.get("rule_hits") or [])
    # Debug includes sources meta
    assert "debug" in body
    assert "sources" in body["debug"]
    assert isinstance(body["debug"]["sources"], list)
    assert body["debug"]["sources"][0]["filename"] == "note.txt"


def test_multipart_generates_request_id():
    r = client.post("/guardrail/evaluate_multipart", data={"text": "hello"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body.get("request_id"), str)
