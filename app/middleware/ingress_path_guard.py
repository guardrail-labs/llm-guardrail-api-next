from __future__ import annotations

import re
import urllib.parse
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import ingress_path_violation_report

# Unicode characters which are easily confused with "/" or "\".
# See: U+2215 DIVISION SLASH, U+2044 FRACTION SLASH, U+2216 SET MINUS
# Also include backslash U+005C for Windows style traversal.
_SLASH_HOMOGLYPHS = {"\u2215", "\u2044", "\u2216", "\\"}

# After decoding, treat both "/" and "\" as separators when checking traversal.
_SEP_PATTERN = re.compile(r"[\\/]+")

# Quick reject: if raw path contains obviously suspicious encodings.
# %2e%2e, %2F, %5C in any case, overlong dot encodings, or mixed separators.
_SUSPICIOUS_RAW = re.compile(r"(%2e){2}|%2f|%5c|%2F|%5C|%u2215|%u2044|%u2216", re.IGNORECASE)


# Two-step decode to catch double-encoding tricks like %252e%252e => %2e%2e => ..
def _decode_once(p: str) -> str:
    return urllib.parse.unquote(p, errors="strict")


def _decode_twice(p: str) -> str:
    try:
        first = _decode_once(p)
    except Exception:
        # Malformed percent-escapes; keep original for signals
        return p
    try:
        return _decode_once(first)
    except Exception:
        return first


def _contains_homoglyph_slash(p: str) -> bool:
    return any(ch in _SLASH_HOMOGLYPHS for ch in p)


def _looks_traversal(decoded: str) -> bool:
    # Normalize separators to "/" and collapse repeats
    norm = _SEP_PATTERN.sub("/", decoded)
    # Any "/../" or leading "../" or trailing "/.." indicates traversal intent.
    if "/../" in norm or norm.startswith("../") or norm.endswith("/.."):
        return True
    # Dot-dot segments even if surrounded by weird spacing
    parts = [seg.strip() for seg in norm.split("/")]
    return any(seg == ".." for seg in parts)


class IngressPathGuardMiddleware(BaseHTTPMiddleware):
    """
    Blocks obvious path traversal and double-encoding URL attacks at ingress.

    - Does NOT rewrite paths; either passes through or returns 400.
    - Signals recorded via ingress_path_violation_report().
    - Cheap checks on raw path, single decode, and double decode.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        scope = request.scope
        raw_path_bytes = scope.get("raw_path") or scope.get("path", "").encode()
        try:
            raw_path = raw_path_bytes.decode("utf-8")
        except Exception:
            try:
                raw_path = raw_path_bytes.decode("latin-1", errors="ignore")
            except Exception:
                raw_path = str(scope.get("path", ""))

        suspicious = 0
        reason = ""

        # 0) Quick raw-path heuristics (cheap)
        if _SUSPICIOUS_RAW.search(raw_path):
            suspicious = 1
            reason = "raw-encodings"

        # 1) Homoglyph slash in raw or decoded
        homoglyph = _contains_homoglyph_slash(raw_path)

        # 2) Decode once and twice; check traversal after each
        once = _decode_once(raw_path)
        twice = _decode_twice(raw_path)

        if not suspicious and (_looks_traversal(once) or _looks_traversal(twice)):
            suspicious = 1
            reason = "traversal"

        if not suspicious and (homoglyph or _contains_homoglyph_slash(once)):
            suspicious = 1
            reason = "homoglyph-slash"

        if suspicious:
            ingress_path_violation_report(reason=reason)
            return Response(
                status_code=400,
                media_type="application/json",
                content=b'{"error":"bad_request","detail":"invalid path"}',
            )

        return await call_next(request)
