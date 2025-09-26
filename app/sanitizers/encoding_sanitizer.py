from __future__ import annotations

import base64
import binascii
import math
import re
import urllib.parse
from typing import Dict, Tuple

_MAX_DECODE_BYTES = 64 * 1024  # 64 KiB safety cap

# Heuristic patterns for encoded strings
_RE_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_RE_HEX = re.compile(r"^[0-9A-Fa-f]+$")
# Consider URL-encoded if it has %XX patterns or pluses and decodes to more ASCII
_RE_URL_HINT = re.compile(r"%(?:[0-9A-Fa-f]{2})")

def _shannon_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    freq: Dict[int, int] = {}
    for b in s:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    n = float(len(s))
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _maybe_decode_base64(text: str) -> Tuple[str, int]:
    t = text.strip()
    if len(t) < 8:
        return text, 0
    if len(t) % 2 == 0 and _RE_HEX.match(t):
        # Prefer hex decoding for pure hex strings to avoid false positives.
        return text, 0
    if len(t) % 4 != 0:
        return text, 0
    if not _RE_BASE64.match(t):
        return text, 0
    try:
        data = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return text, 0
    if not data or len(data) > _MAX_DECODE_BYTES:
        return text, 0
    # If entropy is extremely high and printable ratio is tiny,
    # keep it decoded anyway so downstream scanners can see it.
    try:
        decoded = data.decode("utf-8", errors="replace")
    except Exception:
        return text, 0
    return decoded, 1


def _maybe_decode_hex(text: str) -> Tuple[str, int]:
    t = text.strip()
    if len(t) < 8 or len(t) % 2 != 0:
        return text, 0
    if not _RE_HEX.match(t):
        return text, 0
    try:
        data = binascii.unhexlify(t)
    except binascii.Error:
        return text, 0
    if not data or len(data) > _MAX_DECODE_BYTES:
        return text, 0
    try:
        decoded = data.decode("utf-8", errors="replace")
    except Exception:
        return text, 0
    return decoded, 1


def _maybe_decode_url(text: str) -> Tuple[str, int]:
    if ("%2" not in text and "%3" not in text and "+" not in text):
        # Fast path skip when no obvious hints
        if not _RE_URL_HINT.search(text):
            return text, 0
    decoded = urllib.parse.unquote_plus(text)
    if decoded == text:
        return text, 0
    if len(decoded.encode("utf-8")) > _MAX_DECODE_BYTES:
        return text, 0
    return decoded, 1


def decode_string_once(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Attempts one layer of decoding in priority order:
    base64 -> hex -> url.

    Returns (decoded_or_original, stats).
    """
    stats = {"decoded_base64": 0, "decoded_hex": 0, "decoded_url": 0, "changed": 0}

    out, flag = _maybe_decode_base64(text)
    if flag:
        stats["decoded_base64"] = 1
        stats["changed"] = 1
        return out, stats

    out, flag = _maybe_decode_hex(text)
    if flag:
        stats["decoded_hex"] = 1
        stats["changed"] = 1
        return out, stats

    out, flag = _maybe_decode_url(text)
    if flag:
        stats["decoded_url"] = 1
        stats["changed"] = 1
        return out, stats

    return text, stats
