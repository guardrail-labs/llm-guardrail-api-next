from __future__ import annotations

import zipfile
from pathlib import Path

from app.services.detect.hidden_text import detect_hidden_text_docx

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>
"""

DOCUMENT_WITH_VANISH = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:rPr><w:vanish/></w:rPr>
        <w:t>hidden text</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
"""


def _write_min_docx(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", DOCUMENT_WITH_VANISH)


def test_docx_detects_vanish(tmp_path: Path) -> None:
    p = tmp_path / "has-vanish.docx"
    _write_min_docx(p)
    out = detect_hidden_text_docx(p)
    assert any(f.reason == "w:vanish" for f in out)
    # Provides location within archive
    assert any(f.location == "word/document.xml" for f in out)
