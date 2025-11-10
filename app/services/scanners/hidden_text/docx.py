from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from typing import List

# WordprocessingML namespace
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

_DOC_PARTS = (
    "word/document.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/header1.xml",
    "word/header2.xml",
    "word/header3.xml",
    "word/footer1.xml",
    "word/footer2.xml",
    "word/footer3.xml",
)


def _docx_bytes_to_zip(buf: bytes) -> zipfile.ZipFile | None:
    try:
        return zipfile.ZipFile(io.BytesIO(buf))
    except Exception:
        return None


def _scan_part(z: zipfile.ZipFile, name: str, reasons: List[str]) -> None:
    try:
        with z.open(name) as fp:
            tree = ET.parse(fp)
    except Exception:
        return
    root = tree.getroot()
    # Hidden text: <w:vanish/> or <w:rPr><w:vanish/></w:rPr>
    if root.findall(f".//{_W}vanish"):
        reasons.append("docx_vanish")
    # Track changes (insertions/deletions)
    if root.findall(f".//{_W}ins"):
        reasons.append("docx_track_ins")
    if root.findall(f".//{_W}del"):
        reasons.append("docx_track_del")


def _scan_comments(z: zipfile.ZipFile, reasons: List[str]) -> None:
    try:
        with z.open("word/comments.xml") as fp:
            ET.parse(fp)
            reasons.append("docx_comments")
    except Exception:
        return


def scan_docx_for_hidden(buf: bytes) -> List[str]:
    reasons: List[str] = []
    z = _docx_bytes_to_zip(buf)
    if not z:
        return reasons
    for p in _DOC_PARTS:
        if p in z.namelist():
            _scan_part(z, p, reasons)
    _scan_comments(z, reasons)
    # de-dup while preserving order
    seen: set[str] = set()
    out: List[str] = []
    for r in reasons:
        if r not in seen:
            out.append(r)
            seen.add(r)
    return out
