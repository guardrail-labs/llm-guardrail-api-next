from __future__ import annotations

import random
import string

import pytest

from app.idempotency.log_utils import _mask_key


@pytest.mark.parametrize("key", ["a", "ab", "abcdefg", "x" * 16, "y" * 32, "z" * 64])
@pytest.mark.parametrize("prefix_len", [0, 1, 2, 4, 8, 16, 64])
def test_mask_never_reveals_full_key(key: str, prefix_len: int) -> None:
    masked = _mask_key(key, prefix_len)
    assert masked is not None
    assert masked != key
    # Full key must never be present verbatim
    assert key not in masked  # type: ignore[arg-type]
    # Ellipsis + 8-char tail always present
    assert "…" in masked
    assert len(masked.split("…")[-1]) == 8
    # Lines should be comfortably under 100 chars (informal guard)
    assert len(masked) < 100


def _rand_key(n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_:.@"
    return "".join(random.choice(alphabet) for _ in range(n))


@pytest.mark.parametrize("length", [1, 2, 3, 7, 8, 15, 31, 32, 63, 64])
def test_random_lengths_do_not_leak_entire_value(length: int) -> None:
    key = _rand_key(length)
    # Try several prefix lengths, including overly large ones
    for pl in [0, 1, 2, 4, 8, 16, 128]:
        masked = _mask_key(key, pl)
        assert masked is not None
        assert masked != key
        assert key not in masked  # type: ignore[arg-type]
        assert "…" in masked
        assert len(masked.split("…")[-1]) == 8


def test_falsy_input_passthrough() -> None:
    assert _mask_key(None, 4) is None
    assert _mask_key("", 4) == ""


def test_bad_prefix_len_is_safely_handled() -> None:
    # type: ignore[arg-type] ensures mypy is not upset where needed by callers,
    # but here we pass a bad value indirectly by using __anext__ style or similar.
    class BadInt:
        def __int__(self) -> int:
            raise ValueError("nope")

    masked = _mask_key("abcdef", BadInt())  # type: ignore[arg-type]
    assert masked is not None
    assert masked != "abcdef"
    assert "…" in masked
    assert len(masked.split("…")[-1]) == 8
