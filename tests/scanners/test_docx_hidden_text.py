import io
import zipfile

from app.services.scanners.hidden_text.docx import scan_docx_for_hidden


def _mk_docx_with(xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "word/document.xml",
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"{xml}</w:document>"
        )
    return buf.getvalue()


def test_docx_detects_vanish():
    doc = _mk_docx_with("<w:r><w:rPr><w:vanish/></w:rPr><w:t>x</w:t></w:r>")
    out = scan_docx_for_hidden(doc)
    assert "docx_vanish" in out
