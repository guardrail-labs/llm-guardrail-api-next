from __future__ import annotations

from app.services.media.safe_image import FLAG, ImageReencoder, safe_transform


class _MockReenc(ImageReencoder):
    def strip_and_reencode(self, b: bytes) -> bytes:
        return b + b"x"


def test_safe_image_sets_flag_and_can_reencode():
    src = b"\x89PNG...."
    res = safe_transform(src, reencoder=_MockReenc())
    assert FLAG in res.rule_hits
    assert res.image_bytes.endswith(b"x")
    assert res.debug["reencoded"] is True


def test_safe_image_noop_is_ok():
    src = b"jpeg"
    res = safe_transform(src)  # Noop
    assert FLAG in res.rule_hits
    assert res.image_bytes == src
    assert res.debug["reencoded"] is False
