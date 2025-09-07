from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_image_ocr_triggers_redaction_when_enabled(monkeypatch):
    # Enable OCR
    monkeypatch.setenv("OCR_ENABLED", "1")

    # Monkeypatch OCR to avoid external deps
    import app.services.ocr as ocr
    monkeypatch.setattr(
        ocr, "extract_from_image", lambda b: "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )

    png_bytes = b"\x89PNG\r\n\x1a\n" + b"dummy"
    files = [("files", ("x.png", png_bytes, "image/png"))]

    r = client.post("/guardrail/evaluate", files=files, data={"text": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "[REDACTED:OPENAI_KEY]" in body["text"]
    assert "secrets:*" in (body.get("rule_hits") or [])


def test_pdf_textlayer_extraction_redacts_hidden_text(monkeypatch):
    # Enable OCR
    monkeypatch.setenv("OCR_ENABLED", "1")
    # Ensure fallback is off; we want text-layer path
    monkeypatch.delenv("OCR_PDF_FALLBACK", raising=False)

    import app.services.ocr as ocr
    # Simulate pdfminer extraction returning hidden secret
    monkeypatch.setattr(
        ocr, "extract_from_pdf", lambda b: ("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ", True)
    )
    monkeypatch.setattr(
        ocr,
        "extract_pdf_with_optional_ocr",
        lambda b: ("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ", "textlayer"),
    )

    pdf_bytes = b"%PDF-1.4\n%dummy\n"
    files = [("files", ("doc.pdf", pdf_bytes, "application/pdf"))]

    r = client.post("/guardrail/evaluate", files=files, data={"text": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "[REDACTED:OPENAI_KEY]" in body["text"]
    assert "secrets:*" in (body.get("rule_hits") or [])


def test_ocr_disabled_keeps_legacy_behavior(monkeypatch):
    # Ensure OCR is off
    monkeypatch.setenv("OCR_ENABLED", "0")

    png_bytes = b"\x89PNG\r\n\x1a\n" + b"dummy"
    files = [("files", ("x.png", png_bytes, "image/png"))]
    r = client.post("/guardrail/evaluate", files=files, data={"text": ""})
    assert r.status_code == 200
    body = r.json()
    # With OCR disabled, we should NOT see redacted text; just the marker and action allow
    assert body["action"] == "allow"
    assert "[IMAGE:x.png]" in body["text"] or body["text"].startswith("[IMAGE:")

