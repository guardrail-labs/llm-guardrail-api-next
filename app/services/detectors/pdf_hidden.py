import os
from typing import List, Tuple

# Feature flag: defaults to enabled
ENABLED = os.getenv("PDF_DETECTOR_ENABLED", "true").lower() not in {"0", "false", "no"}


def _extract_text(pdf_bytes: bytes) -> Tuple[List[str], List[str]]:
    """Mock extractor that separates visible and hidden text.

    The input is expected to use simple markers:
    - lines beginning with ``VISIBLE:`` are treated as visible text
    - lines beginning with ``HIDDEN:`` are considered hidden
    This is a stand-in for a real PDF text extractor.
    """
    text = pdf_bytes.decode("utf-8", errors="ignore")
    visible: List[str] = []
    hidden: List[str] = []
    for line in text.splitlines():
        if line.startswith("VISIBLE:"):
            visible.append(line[len("VISIBLE:") :])
        elif line.startswith("HIDDEN:"):
            hidden.append(line[len("HIDDEN:") :])
    return visible, hidden


def sanitize_for_downstream(pdf_bytes: bytes):
    """Return visible text and rule hits for hidden spans."""
    if not ENABLED:
        return "", [], {"spans_count": 0}

    visible, hidden = _extract_text(pdf_bytes)
    rule_hits = []
    if hidden:
        rule_hits.append({"tag": "inj:hidden_text_pdf", "pattern": "hidden_pdf_text"})
    debug = {"spans_count": len(hidden), "samples": hidden[:2]}
    return "\n".join(visible), rule_hits, debug
