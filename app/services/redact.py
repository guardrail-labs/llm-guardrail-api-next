"""Secret redaction helpers (no external deps)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# Patterns roughly match obvious secret shapes
_RE_OPENAI = re.compile(r"sk-[A-Za-z0-9]{20,}")
_RE_AWS_AKID = re.compile(r"AKIA[0-9A-Z]{16}")

# Accept both "-----BEGIN PRIVATE KEY-----" and "-----BEGIN RSA PRIVATE KEY-----"
_PEM_HDR = r"-----BEGIN (?:[^-]+ )?PRIVATE KEY-----"
_PEM_FTR = r"-----END (?:[^-]+ )?PRIVATE KEY-----"
_RE_PEM_HEADER = re.compile(_PEM_HDR)
_RE_PEM_FOOTER = re.compile(_PEM_FTR)
_RE_PEM_BLOCK = re.compile(rf"{_PEM_HDR}[\s\S]*?{_PEM_FTR}")


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

    # Replace full PEM blocks if present; otherwise replace header/footer if seen
    if _RE_PEM_BLOCK.search(out):
        kinds.append("pem_key")
        out = _RE_PEM_BLOCK.sub(pem_mask, out)
    else:
        if _RE_PEM_HEADER.search(out):
            kinds.append("pem_key")
            out = _RE_PEM_HEADER.sub(pem_mask, out)
        if _RE_PEM_FOOTER.search(out):
            if "pem_key" not in kinds:
                kinds.append("pem_key")
            out = _RE_PEM_FOOTER.sub(pem_mask, out)

    return RedactionResult(text=out, kinds=kinds)
