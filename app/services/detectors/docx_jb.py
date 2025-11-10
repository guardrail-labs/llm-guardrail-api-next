"""
DOCX jailbreak & social-engineering detector.

- Pattern families:
  * inj:roleplay_jailbreak
  * inj:override_safety
  * exfil:credentials_request
  * soceng:coercion_emotive

Dependency-free: uses an extractor protocol so CI doesn't need python-docx.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Protocol, Tuple
from xml.etree import ElementTree as ET

# ---- Rule IDs ---------------------------------------------------------------
R_ROLEPLAY = "inj:roleplay_jailbreak"
R_OVERRIDE = "inj:override_safety"
R_EXFIL = "exfil:credentials_request"
R_COERCE = "soceng:coercion_emotive"


# ---- Extractor Protocol -----------------------------------------------------
class DocxExtractor(Protocol):
    def extract_paragraphs(self, docx_bytes: bytes) -> Iterable[str]: ...


class DefaultDocxExtractor:
    def extract_paragraphs(self, docx_bytes: bytes) -> Iterable[str]:
        # Fallback: treat as empty => no hits (safe default for CI)
        return []


# ---- Patterns ---------------------------------------------------------------
_PATTERNS: Dict[str, re.Pattern[str]] = {
    R_ROLEPLAY: re.compile(
        r"(?i)\b(pretend|role[\-\s]*play|act\s+as)\b.*\b(teen|child|hacker|admin)\b"
    ),
    R_OVERRIDE: re.compile(
        r"(?i)\b(ignore|bypass|disable)\b.*\b(safety|guardrail|filter|policy)\b"
    ),
    R_EXFIL: re.compile(r"(?i)\b(source\s*code|server\s*credentials|api\s*key|password|token)\b"),
    R_COERCE: re.compile(
        r"(?i)\b(save my (mom|mother|grand(mother|ma))|someone is in danger|life or death)\b"
    ),
}

_DOCX_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


@dataclass
class DetectionResult:
    rule_hits: List[str]
    sanitized_text: str
    debug: Dict[str, Any]


def _scan_lines(lines: List[str]) -> Tuple[List[str], List[str], Dict[str, Any]]:
    hits: List[str] = []
    keep: List[str] = []
    samples: Dict[str, List[str]] = {rid: [] for rid in _PATTERNS}

    for ln in lines:
        text = (ln or "").strip()
        if not text:
            continue

        line_hit = False
        for rid, pat in _PATTERNS.items():
            if pat.search(text):
                if rid not in hits:
                    hits.append(rid)
                if len(samples[rid]) < 3:
                    samples[rid].append(text[:200])
                line_hit = True

        if not line_hit:
            keep.append(text)

    debug = {
        "samples": samples,
        "kept_count": len(keep),
        "lines_scanned": len(lines),
    }
    return hits, keep, debug


def _scan_hidden_runs(docx_bytes: bytes) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    samples: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(docx_bytes)) as zf:
            xml = zf.read("word/document.xml")
    except Exception:
        return reasons, samples

    try:
        root = ET.fromstring(xml)
    except Exception:
        return reasons, samples

    parts: List[str] = []
    for run in root.findall(".//w:r", _DOCX_NS):
        rpr = run.find("w:rPr", _DOCX_NS)
        texts = [t.text for t in run.findall("w:t", _DOCX_NS) if t.text]
        txt = "".join(texts).strip()
        if rpr is None or not txt:
            continue
        run_reasons: List[str] = []
        if rpr.find("w:vanish", _DOCX_NS) is not None:
            run_reasons.append("docx:hidden_run")
        color_el = rpr.find("w:color", _DOCX_NS)
        shd_el = rpr.find("w:shd", _DOCX_NS)
        sz_el = rpr.find("w:sz", _DOCX_NS)
        color_val = color_el.get(f"{{{_DOCX_NS['w']}}}val") if color_el is not None else None
        shd_val = shd_el.get(f"{{{_DOCX_NS['w']}}}fill") if shd_el is not None else None
        sz_val = sz_el.get(f"{{{_DOCX_NS['w']}}}val") if sz_el is not None else None

        def _is_white(v: str | None) -> bool:
            return bool(v and v.lower() in {"fff", "ffffff"})

        if _is_white(color_val) and (_is_white(shd_val) or shd_val is None):
            run_reasons.append("docx:white_on_white")
        try:
            if sz_val is not None and int(sz_val) <= 8:
                run_reasons.append("docx:tiny_font")
        except Exception:
            pass

        if run_reasons:
            parts.append(" ".join(txt.split()))
            reasons.extend(run_reasons)

    sample = " ".join(parts).strip()[:200]
    if sample:
        samples.append(sample)
    uniq_reasons = list(dict.fromkeys(reasons))
    return uniq_reasons, samples


def detect_and_sanitize_docx(
    docx_bytes: bytes, extractor: DocxExtractor | None = None
) -> DetectionResult:
    """
    Scan DOCX paragraphs for jailbreak / social-engineering cues; return
    rule hits and sanitized text that excludes matched lines.
    """
    extractor = extractor or DefaultDocxExtractor()
    lines = list(extractor.extract_paragraphs(docx_bytes))
    rule_hits, keep, dbg = _scan_lines(lines)
    hidden_reasons, hidden_samples = _scan_hidden_runs(docx_bytes)
    rule_hits.extend(hidden_reasons)
    sanitized = "\n".join(ln for ln in keep if ln)
    dbg["rule_hits"] = rule_hits
    dbg["hidden_reasons"] = hidden_reasons
    dbg["hidden_samples"] = hidden_samples
    return DetectionResult(rule_hits=rule_hits, sanitized_text=sanitized, debug=dbg)
