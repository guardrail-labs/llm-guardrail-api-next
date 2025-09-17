from __future__ import annotations

import hashlib
import hmac

import app.services.webhooks as wh


def _hex(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def test_v0_signature_body_only(monkeypatch):
    body = b'{"ok":true}'
    secret = b"s3cr3t"

    # Force mode to body (v0)
    monkeypatch.setattr(
        "app.services.webhooks.get_webhook_signing",
        lambda: {"mode": "body", "dual": True},
    )

    headers = wh._signing_headers(body, secret)
    assert "X-Guardrail-Signature" in headers
    assert "X-Guardrail-Signature-V1" not in headers
    assert "X-Guardrail-Timestamp" not in headers

    provided = headers["X-Guardrail-Signature"].split("=", 1)[1]
    assert provided == _hex(secret, body)


def test_v1_signature_ts_body_dual(monkeypatch):
    body = b'{"ok":true}'
    secret = b"s3cr3t"
    # deterministic timestamp
    monkeypatch.setattr(wh.time, "time", lambda: 1_700_000_000)

    # Enable v1 with dual headers
    monkeypatch.setattr(
        "app.services.webhooks.get_webhook_signing",
        lambda: {"mode": "ts_body", "dual": True},
    )

    headers = wh._signing_headers(body, secret)
    assert headers["X-Guardrail-Timestamp"] == "1700000000"
    assert "X-Guardrail-Signature" in headers
    assert "X-Guardrail-Signature-V1" in headers

    v0 = headers["X-Guardrail-Signature"].split("=", 1)[1]
    v1 = headers["X-Guardrail-Signature-V1"].split("=", 1)[1]
    assert v0 == _hex(secret, body)

    preimage = b"1700000000\n" + body
    assert v1 == _hex(secret, preimage)


def test_v1_signature_ts_body_replace_only(monkeypatch):
    body = b'{"ok":true}'
    secret = b"s3cr3t"
    monkeypatch.setattr(wh.time, "time", lambda: 1_700_000_001)

    # Enable v1 without dual header
    monkeypatch.setattr(
        "app.services.webhooks.get_webhook_signing",
        lambda: {"mode": "ts_body", "dual": False},
    )

    headers = wh._signing_headers(body, secret)
    assert headers["X-Guardrail-Timestamp"] == "1700000001"
    assert "X-Guardrail-Signature" not in headers  # only V1 emitted
    assert "X-Guardrail-Signature-V1" in headers

    preimage = b"1700000001\n" + body
    v1 = headers["X-Guardrail-Signature-V1"].split("=", 1)[1]
    assert v1 == _hex(secret, preimage)
