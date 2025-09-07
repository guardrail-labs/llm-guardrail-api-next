from __future__ import annotations

import gzip
import hashlib
import hmac
import importlib
import json
import time

from fastapi.testclient import TestClient


def _load_app(monkeypatch) -> TestClient:
    monkeypatch.setenv("AUDIT_RECEIVER_REQUIRE_SIGNATURE", "1")
    monkeypatch.setenv("AUDIT_RECEIVER_ENFORCE_TS", "1")
    monkeypatch.setenv("AUDIT_RECEIVER_SIGNING_SECRET", "primary")
    monkeypatch.setenv("AUDIT_RECEIVER_SIGNING_SECRET_SECONDARY", "secondary")

    import examples.audit_sink.receiver as r

    importlib.reload(r)
    return TestClient(r.app)


def test_receiver_accepts_gzip_and_secondary_secret(monkeypatch):
    client = _load_app(monkeypatch)

    body = json.dumps({"a": 1}).encode("utf-8")
    ts = str(int(time.time()))
    msg = ts.encode("utf-8") + b"." + body
    sig = hmac.new(b"secondary", msg, hashlib.sha256).hexdigest()
    compressed = gzip.compress(body)

    r = client.post(
        "/audit",
        data=compressed,
        headers={
            "Content-Encoding": "gzip",
            "X-Signature-Ts": ts,
            "X-Signature": f"sha256={sig}",
        },
    )

    assert r.status_code == 200
    assert r.json() == {"ok": True, "deduped": False}
