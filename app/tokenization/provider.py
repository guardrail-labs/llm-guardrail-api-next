from __future__ import annotations

from typing import List

# Optional dependency: if tiktoken is present we'll use it.
# We do not add a hard dependency; fallback is a simple tokenizer.
try:
    import tiktoken
except Exception:  # pragma: no cover
    tiktoken = None


def _fallback_tokenize(text: str) -> List[str]:
    """
    Simple, deterministic tokenizer:
    - splits on non-alnum
    - collapses empties
    """
    out: List[str] = []
    buf: List[str] = []
    for ch in text:
        if ch.isalnum():
            buf.append(ch)
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return out


def tokenize(text: str) -> List[str]:
    """
    Tokenize with tiktoken if available (gpt-4o encoding),
    else fallback to a simple alnum tokenizer.
    """
    if tiktoken is None:
        return _fallback_tokenize(text)
    try:
        enc = tiktoken.get_encoding("o200k_base")
    except Exception:
        return _fallback_tokenize(text)
    # Map token ids back to text pieces for window joins.
    # For unknown decodes, use fallback.
    try:
        ids = enc.encode(text)
        parts = [enc.decode([tid]) for tid in ids]
        return parts
    except Exception:
        return _fallback_tokenize(text)
