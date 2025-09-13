from __future__ import annotations

from typing import Any, Dict, cast

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _fake_pdf_bytes() -> bytes:
    # Minimal ASCII-friendly bytes so raw.decode() works in the fallback path.
    return b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"


def _patch_hidden(monkeypatch, payload: Dict[str, Any]) -> None:
    import app.services.detectors.pdf_hidden as pdf_hidden

    def _fake_detect(_: bytes) -> Dict[str, Any]:
        return payload

    monkeypatch.setattr(pdf_hidden, "detect_hidden_text", _fake_detect)


def _post_eval_multipart() -> Dict[str, Any]:
    files = [("files", ("note.pdf", _fake_pdf_bytes(), "application/pdf"))]
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    # r.json() is Any; cast for mypy
    return cast(Dict[str, Any], r.json())


def test_pdf_hidden_string_values_are_coerced(monkeypatch) -> None:
    """
    Non-list types for reasons/samples still produce a valid response.
    """
    _patch_hidden(
        monkeypatch,
        {"found": True, "reasons": "rgb_near_white", "samples": "ghosttext"},
    )
    body = _post_eval_multipart()
    assert "[HIDDEN_TEXT_DETECTED:" in body["text"]


def test_pdf_hidden_none_values_are_ignored(monkeypatch) -> None:
    """
    None/empty values handled; HIDDEN block still present.
    """
    _patch_hidden(monkeypatch, {"found": True, "reasons": None, "samples": None})
    body = _post_eval_multipart()
    assert "[HIDDEN_TEXT_DETECTED:" in body["text"]


def test_pdf_hidden_list_values_also_work(monkeypatch) -> None:
    """
    Lists continue to work the same.
    """
    _patch_hidden(
        monkeypatch,
        {
            "found": True,
            "reasons": ["rgb_near_white", "tiny_font"],
            "samples": ["a", "b", "c"],
        },
    )
    body = _post_eval_multipart()
    assert "[HIDDEN_TEXT_DETECTED:" in body["text"]
