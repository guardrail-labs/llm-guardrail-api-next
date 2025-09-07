from __future__ import annotations

from app.services.media.safe_image import (
    FLAG_OPAQUE_MEDIA,
    ImageReencoder,
    safe_transform,
)


class _MockReencoder(ImageReencoder):
    def strip_and_reencode(self, b: bytes) -> bytes:
        # Simulate a deterministic re-encode (e.g., metadata removed)
        return b + b"x"


def test_safe_image_sets_flag_and_can_reencode():
    src = b"\x89PNG\r\n\x1a\n..."
    res = safe_transform(src, reencoder=_MockReencoder())
    assert FLAG_OPAQUE_MEDIA in res.rule_hits
    assert res.image_bytes.endswith(b"x")
    assert res.debug["reencoded"] is True
    assert res.debug["input_size"] == len(src)
    assert res.debug["output_size"] == len(src) + 1


def test_safe_image_noop_is_ok():
    src = b"jpeg-bytes"
    res = safe_transform(src)  # Noop reencoder by default
    assert FLAG_OPAQUE_MEDIA in res.rule_hits
    assert res.image_bytes == src
    assert res.debug["reencoded"] is False
    assert res.debug["input_size"] == len(src)
    assert res.debug["output_size"] == len(src)
