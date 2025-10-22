from __future__ import annotations

from app.services.stream_redactor import RedactorBoundaryWriter


def test_redacts_split_secret_across_chunks():
    rbw = RedactorBoundaryWriter()
    out = []
    out += rbw.feed(b"sk-")
    out += rbw.feed(b"ABCDEF0123456789more\n")
    out += rbw.flush()
    full = b"".join(out).decode("utf-8")
    assert "[REDACTED]" in full
    assert "sk-ABCDEF0123456789" not in full


def test_non_sensitive_passes_through():
    rbw = RedactorBoundaryWriter()
    out = []
    out += rbw.feed(b"hello world. ")
    out += rbw.feed(b"streaming rocks\n")
    out += rbw.flush()
    s = b"".join(out).decode("utf-8")
    assert "hello world." in s
    assert "streaming rocks" in s
