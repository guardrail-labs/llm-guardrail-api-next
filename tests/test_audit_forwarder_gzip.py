from __future__ import annotations

import gzip
import hashlib
import hmac
import json

from app.services import audit_forwarder as af


def test_post_with_gzip_and_hmac(monkeypatch):
    secret = "topsecret"
    monkeypatch.setenv("AUDIT_FORWARD_SIGNING_SECRET", secret)
    monkeypatch.setenv("AUDIT_FORWARD_COMPRESS", "1")

    captured = {}

    class FakeResp:
        status = 200

        def read(self) -> bytes:  # pragma: no cover - simple
            return b"ok"

    class FakeConn:
        def request(self, method, path, body=None, headers=None):
            captured["body"] = body
            captured["headers"] = headers

        def getresponse(self):  # pragma: no cover - simple
            return FakeResp()

        def close(self):  # pragma: no cover - simple
            pass

    monkeypatch.setattr(af, "_http_connection_for", lambda url: FakeConn())

    status, text = af._post("http://example.com/audit", "k", {"a": 1})
    assert status == 200
    assert text == "ok"

    hdrs = captured["headers"]
    assert hdrs.get("Content-Encoding") == "gzip"

    decompressed = gzip.decompress(captured["body"])
    assert json.loads(decompressed.decode("utf-8")) == {"a": 1}

    ts = hdrs["X-Signature-Ts"]
    provided = hdrs["X-Signature"].split("=", 1)[1]
    msg = ts.encode("utf-8") + b"." + decompressed
    expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    assert provided == expected

