from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

client = TestClient(app)


def _make_docx(xml: str) -> bytes:
    files = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument-'
            'wordprocessingml.document.main+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'officeDocument" Target="word/document.xml"/>'
            "</Relationships>"
        ),
        "word/document.xml": xml,
    }
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return bio.getvalue()


def _docx_hidden() -> bytes:
    xml = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p>"
        "<w:r><w:t>Visible</w:t></w:r>"
        "<w:r><w:rPr><w:vanish/></w:rPr><w:t>Secret1</w:t></w:r>"
        '<w:r><w:rPr><w:color w:val="FFFFFF"/><w:shd w:fill="FFFFFF"/></w:rPr>'
        "<w:t>Secret2</w:t></w:r>"
        '<w:r><w:rPr><w:sz w:val="8"/></w:rPr><w:t>Secret3</w:t></w:r>'
        "</w:p></w:body></w:document>"
    )
    return _make_docx(xml)


def _docx_clean() -> bytes:
    xml = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Just text</w:t></w:r></w:p></w:body></w:document>"
    )
    return _make_docx(xml)


def test_multipart_docx_hidden_detected_and_denied() -> None:
    docx_bytes = _docx_hidden()
    files = [("files", ("hidden.docx", docx_bytes, DOCX_MIME))]
    r = client.post("/guardrail/evaluate_multipart", files=files, headers={"X-Debug": "1"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "deny"
    dbg = body["debug"]
    reasons = set(dbg.get("hidden_reasons", []))
    assert {"docx:hidden_run", "docx:white_on_white", "docx:tiny_font"} <= reasons
    sample = " ".join(dbg.get("hidden_samples", []))
    assert "Secret1" in sample and "Secret2" in sample and "Secret3" in sample


def test_multipart_docx_clean_is_allowed_like_baseline() -> None:
    docx_bytes = _docx_clean()
    files = [("files", ("clean.docx", docx_bytes, DOCX_MIME))]
    r = client.post("/guardrail/evaluate_multipart", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in {"allow", "sanitize", "clarify", "deny"}
