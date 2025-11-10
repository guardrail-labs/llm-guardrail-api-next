from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union


@dataclass(frozen=True)
class HiddenTextFinding:
    filetype: str  # "html" | "docx"
    reason: str  # short tag like "display:none", "w:vanish"
    location: Optional[str] = None  # e.g., "line:col" or path within archive
    snippet: Optional[str] = None  # small excerpt if available


# --------------------------- HTML detection ----------------------------------


_CSS_WS = re.compile(r"\s+")
_HEX_COLOR = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})")


def _normalize_css(css: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for decl in css.split(";"):
        if not decl.strip():
            continue
        if ":" not in decl:
            continue
        k, v = decl.split(":", 1)
        props[_CSS_WS.sub("", k.strip().lower())] = v.strip().lower()
    return props


def _same_color(a: str, b: str) -> bool:
    # Support #rgb and #rrggbb equivalence
    def norm(x: str) -> Optional[str]:
        m = _HEX_COLOR.fullmatch(x.strip())
        if not m:
            return None
        hx = m.group(0).lower()
        if len(hx) == 4:  # #rgb -> #rrggbb
            r, g, bl = hx[1], hx[2], hx[3]
            return f"#{r}{r}{g}{g}{bl}{bl}"
        return hx

    na, nb = norm(a), norm(b)
    return (na is not None) and (na == nb)


def detect_hidden_text_html(html: str) -> List[HiddenTextFinding]:
    findings: List[HiddenTextFinding] = []
    # Cheap scanning: we avoid external parsers to keep dependencies zero.
    # 1) Inline style checks
    #    - display:none
    #    - visibility:hidden
    #    - font-size:0 / font-size:0px
    style_pat = re.compile(r"""style\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
    for m in style_pat.finditer(html):
        raw = m.group(1)
        props = _normalize_css(raw)
        loc = f"pos:{m.start()}-{m.end()}"
        if props.get("display") == "none":
            findings.append(HiddenTextFinding("html", "display:none", location=loc, snippet=raw))
        if props.get("visibility") == "hidden":
            findings.append(
                HiddenTextFinding("html", "visibility:hidden", location=loc, snippet=raw)
            )
        if props.get("font-size") in {"0", "0px", "0rem", "0em"}:
            findings.append(HiddenTextFinding("html", "font-size:0", location=loc, snippet=raw))
        # color equals background-color (simple hex comparison)
        col, bg = props.get("color"), props.get("background-color")
        if col and bg and _same_color(col, bg):
            findings.append(
                HiddenTextFinding("html", "color==background-color", location=loc, snippet=raw)
            )

    # 2) Hidden attributes
    #    - hidden
    #    - aria-hidden="true"
    hidden_attr_pat = re.compile(r"<([a-z0-9:_-]+)\b[^>]*\bhidden\b", re.IGNORECASE)
    for m in hidden_attr_pat.finditer(html):
        loc = f"pos:{m.start()}-{m.end()}"
        findings.append(HiddenTextFinding("html", "hidden-attr", location=loc))

    aria_hidden_true_pat = re.compile(r"""aria-hidden\s*=\s*["']\s*true\s*["']""", re.IGNORECASE)
    for m in aria_hidden_true_pat.finditer(html):
        loc = f"pos:{m.start()}-{m.end()}"
        findings.append(HiddenTextFinding("html", "aria-hidden=true", location=loc))

    return findings


# --------------------------- DOCX detection ----------------------------------


# Namespaces of interest
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _docx_read_xml(zf: zipfile.ZipFile, path: str) -> Optional[ET.Element]:
    try:
        data = zf.read(path)
    except KeyError:
        return None
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        return None


def detect_hidden_text_docx(path_or_bytes: Union[str, Path, bytes]) -> List[HiddenTextFinding]:
    """
    Detect hidden text in a DOCX by scanning for <w:vanish/> run properties.
    No external dependencies required.
    """
    findings: List[HiddenTextFinding] = []
    if isinstance(path_or_bytes, (str, Path)):
        zf = zipfile.ZipFile(path_or_bytes, "r")
    else:
        # bytes
        from io import BytesIO

        zf = zipfile.ZipFile(BytesIO(path_or_bytes), "r")

    with zf:
        doc = _docx_read_xml(zf, "word/document.xml")
        if doc is None:
            return findings
        # Search for any w:vanish in run properties
        vanish_tag = f"{{{W_NS}}}vanish"
        for elem in doc.iter():
            if elem.tag == vanish_tag:
                findings.append(
                    HiddenTextFinding(
                        "docx",
                        "w:vanish",
                        location="word/document.xml",
                        snippet="<w:vanish/>",
                    )
                )
                # We can break early after first finding, but keep scanning to
                # return all occurrences for auditing.
    return findings


# --------------------------- Convenience wrapper -----------------------------


def detect_hidden_text(
    content: Union[str, bytes],
    *,
    mime: Optional[str] = None,
    filename: Optional[str] = None,
) -> List[HiddenTextFinding]:
    """
    Dispatch hidden-text detection based on mime/filename or content sniffing.
    For now supports HTML and DOCX.
    """
    fn = (filename or "").lower()
    if isinstance(content, str):
        # Heuristic sniff for HTML
        if (mime and "html" in mime.lower()) or "<html" in content.lower():
            return detect_hidden_text_html(content)
    else:
        # bytes; choose by filename/mime
        if (mime and "officedocument" in mime) or fn.endswith(".docx"):
            return detect_hidden_text_docx(content)
    return []
