"""
Image safe-transformer.

- Treat images as opaque instructions (no code execution).
- Allows metadata stripping / lossless re-encode via a pluggable transformer.
- Flags images as non-interpretable for instruction purposes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol

# Public flag emitted to indicate images must not be treated as instructions.
FLAG_OPAQUE_MEDIA = "opaque_media_noninterpretable"


class ImageReencoder(Protocol):
    """Pluggable re-encoder that can strip metadata or re-pack the image."""

    def strip_and_reencode(self, image_bytes: bytes) -> bytes: ...


class NoopReencoder:
    """Default: do nothing (keeps CI free of heavy image deps)."""

    def strip_and_reencode(self, image_bytes: bytes) -> bytes:
        return image_bytes


@dataclass
class TransformResult:
    image_bytes: bytes
    rule_hits: list[str]
    debug: Dict[str, Any]


def safe_transform(image_bytes: bytes, reencoder: ImageReencoder | None = None) -> TransformResult:
    """
    Returns a transformed image and a flag marking it as non-interpretable input.
    If a reencoder is provided, the image is re-encoded (e.g., EXIF stripped).
    """
    enc = reencoder or NoopReencoder()
    out = enc.strip_and_reencode(image_bytes)
    changed = out != image_bytes

    return TransformResult(
        image_bytes=out,
        rule_hits=[FLAG_OPAQUE_MEDIA],
        debug={
            "reencoded": bool(changed),
            "input_size": len(image_bytes),
            "output_size": len(out),
        },
    )
