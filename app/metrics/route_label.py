from __future__ import annotations

import re
from typing import Final

_UUID_RE: Final = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_HEX_RE: Final = re.compile(r"^[0-9a-fA-F]{8,}$")
_NUM_RE: Final = re.compile(r"^[0-9]{4,}$")
_ULID_RE: Final = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


def _normalize_path(path: str) -> str:
    segs: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if _UUID_RE.match(segment) or _ULID_RE.match(segment):
            segs.append(":id")
        elif len(segment) > 32:
            segs.append(":seg")
        elif _NUM_RE.match(segment) or _HEX_RE.match(segment):
            segs.append(":id")
        else:
            segs.append(segment)
    return "/" + "/".join(segs) if segs else "/"


def route_label(path: str) -> str:
    """Clamp a raw URL path to a safe Prometheus label."""

    if not path:
        return "other"
    trimmed = path.split("?", 1)[0]
    return _normalize_path(trimmed)
