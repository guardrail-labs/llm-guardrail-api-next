"""Secret redaction helpers (no external deps)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# Patterns roughly match obvious secret shapes
_RE_OPENAI = re.compile(r"sk-[A-Za-z0-9]{20,}")
_RE_AWS_AKID = re.compile(r"AKIA[0-9A-Z]{16}")
# Very loose PEM block guard (header/footer). We don't try to match full body safely.
_RE_PEM_HEADER = re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----")
_RE_PEM_FOOTER = re.compile(r"-----END [^-]+ PRIVATE KEY-----")


@dataclass
class RedactionResult:
    text: str
    kinds: List[str]


def redact(text: str, *, openai_mask: str, aws_mask: str, pem_mask: str) -> RedactionResult:
    kinds: List[str] = []
    out = text

    if _RE_OPENAI.search(out):
        kinds.append("openai_key")
        out = _RE_OPENAI.sub(openai_mask, out)

    if _RE_AWS_AKID.search(out):
        kinds.append("aws_akid")
        out = _RE_AWS_AKID.sub(aws_mask, out)

    # Replace any detected PEM header/footer and any content between if both exist
    if _RE_PEM_HEADER.search(out) and _RE_PEM_FOOTER.search(out):
        kinds.append("pem_key")
        out = re.sub(
            r"-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----",
            pem_mask,
            out,
        )
    else:
        # If only header/footer present, still replace individually
        if _RE_PEM_HEADER.search(out):
            kinds.append("pem_key")
            out = _RE_PEM_HEADER.sub(pem_mask, out)
        if _RE_PEM_FOOTER.search(out):
            if "pem_key" not in kinds:
                kinds.append("pem_key")
            out = _RE_PEM_FOOTER.sub(pem_mask, out)

    return RedactionResult(text=out, kinds=kinds)

