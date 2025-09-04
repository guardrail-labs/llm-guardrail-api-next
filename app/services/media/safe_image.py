"""
Image safe-transformer.

- Treats images as opaque instructions (no code execution).
- Allows metadata stripping / lossless re-encode via a pluggable transformer.
- Flags images as non-interpretable for instruction purposes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol

FLAG = "opaque_media_noninterpretable"


class ImageReencoder(Protocol):
    def strip_and_reencode(self, image_bytes: bytes) -> bytes: ...


class NoopReencoder:
    def strip_and_reencode(self, image_bytes: bytes) -> bytes:
        return image_bytes


@dataclass
class TransformResult:
    image_bytes: bytes
    rule_hits: list[str]
    debug: Dict[str, Any]


def safe_transform(
    image_bytes: bytes, reencoder: ImageReencoder | None = None
) -> TransformResult:
    enc = reencoder or NoopReencoder()
    out = enc.strip_and_reencode(image_bytes)
    changed = 1 if out != image_bytes else 0
    return TransformResult(
        image_bytes=out,
        rule_hits=[FLAG],
        debug={"reencoded": bool(changed), "input_size": len(image_bytes), "output_size": len(out)},
    )
