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

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Protocol, Tuple

# Rule IDs
R_ROLEPLAY = "inj:roleplay_jailbreak"
R_OVERRIDE = "inj:override_safety"
R_EXFIL = "exfil:credentials_request"
R_COERCE = "soceng:coercion_emotive"


# ---- Extractor Protocol ------------------------------------------------------
class DocxExtractor(Protocol):
    def extract_paragraphs(self, docx_bytes: bytes) -> Iterable[str]: ...


class DefaultDocxExtractor:
    def extract_paragraphs(self, docx_bytes: bytes) -> Iterable[str]:
        return []  # Fallback: treat as empty => no hits


# ---- Patterns ----------------------------------------------------------------
_PATTERNS: Dict[str, re.Pattern[str]] = {
    R_ROLEPLAY: re.compile(
        r"(?i)\b(pretend|role[-\s]*play|act\s+as)\b.*\b(teen|child|hacker|admin)\b"
    ),
    R_OVERRIDE: re.compile(
        r"(?i)\b(ignore|bypass|disable)\b.*\b(safety|guardrail|filter|policy)\b"
    ),
    R_EXFIL: re.compile(
        r"(?i)\b(source\s*code|server\s*credentials|api\s*key|password|token)\b"
    ),
    R_COERCE: re.compile(
        r"(?i)\b(save my (mom|mother|grand(mother|ma))|someone is in danger|life or death)\b"
    ),
}


@dataclass
class DetectionResult:
    rule_hits: List[str]
    sanitized_text: str
    debug: Dict[str, Any]


def _scan_lines(lines: Iterable[str]) -> Tuple[List[str], List[str], Dict[str, Any]]:
    hits: List[str] = []
    keep: List[str] = []
    samples: Dict[str, List[str]] = {rid: [] for rid in _PATTERNS}

    for ln in lines:
        line_hit = False
        for rid, pat in _PATTERNS.items():
            if pat.search(ln or ""):
                if rid not in hits:
                    hits.append(rid)
                if len(samples[rid]) < 3:
                    samples[rid].append(ln.strip()[:200])
                line_hit = True
        if not line_hit:
            keep.append(ln)

    debug = {"samples": samples, "kept_count": len(keep), "lines_scanned": len(list(lines))}
    return hits, keep, debug


def detect_and_sanitize_docx(
    docx_bytes: bytes, extractor: DocxExtractor | None = None
) -> DetectionResult:
    extractor = extractor or DefaultDocxExtractor()
    lines = list(extractor.extract_paragraphs(docx_bytes))
    rule_hits, keep, dbg = _scan_lines(lines)
    sanitized = "\n".join(s for s in keep if s and s.strip())
    dbg["rule_hits"] = rule_hits
    return DetectionResult(rule_hits=rule_hits, sanitized_text=sanitized, debug=dbg)
