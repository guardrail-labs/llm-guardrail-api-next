from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_pdf_hidden_metrics_emitted(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force a positive detection from the hidden-text detector.
    from app.services.detectors import pdf_hidden as mod

    def _fake_detect(_raw: bytes) -> dict:
        return {
            "found": True,
            "reasons": ["white_on_white", "tiny_font"],
            "samples": ["s1", "s2", "s3"],
        }

    monkeypatch.setattr(mod, "detect_hidden_text", _fake_detect)

    # Minimal fake PDF content.
    pdf_bytes = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"
    files = [("files", ("hidden.pdf", pdf_bytes, "application/pdf"))]

    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200

    # Scrape /metrics exposition for our counters.
    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text

    assert 'guardrail_pdf_hidden_total{reason="white_on_white"}' in text
    assert 'guardrail_pdf_hidden_total{reason="tiny_font"}' in text
    assert "guardrail_pdf_hidden_bytes_total" in text

