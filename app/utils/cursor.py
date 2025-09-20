from __future__ import annotations

import base64
import json
from typing import Tuple


class CursorError(ValueError):
    """Raised when a cursor token cannot be decoded."""


def encode_cursor(ts_ms: int, id_str: str) -> str:
    """Encode the ``(ts_ms, id)`` pair into an opaque, URL-safe cursor."""

    payload = {"ts": int(ts_ms), "id": str(id_str)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(token: str) -> Tuple[int, str]:
    """Decode a cursor token back into the ``(ts_ms, id)`` tuple."""

    if not token:
        raise CursorError("empty cursor")

    pad = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + pad).encode("ascii"))
        obj = json.loads(raw.decode("utf-8"))
        ts = int(obj["ts"])
        _id = str(obj["id"])
    except Exception as exc:  # pragma: no cover - normalization path
        raise CursorError(f"invalid cursor: {exc}") from exc
    return ts, _id
