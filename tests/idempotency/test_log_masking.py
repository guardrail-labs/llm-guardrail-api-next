from __future__ import annotations

import json
from typing import Any, Dict

from app.idempotency.log_utils import log_idempotency_event


def _last_json_record(caplog) -> Dict[str, Any]:
    # take last INFO record from our logger and parse as JSON
    recs = [r for r in caplog.records if r.name == "app.idempotency"]
    assert recs, "no app.idempotency logs captured"
    return json.loads(recs[-1].getMessage())


def test_masking_without_pii(caplog, monkeypatch):
    monkeypatch.setenv("IDEMP_LOG_INCLUDE_PII", "0")
    caplog.set_level("INFO", logger="app.idempotency")

    key = "AbCdEfGh123456"
    log_idempotency_event(
        "replay",
        key=key,
        tenant="t-1",
        headers={"authorization": "secret"},
        fp_prefix="deadbeef",
        replay_count=3,
        wait_ms=12.3,
    )

    data = _last_json_record(caplog)

    # full key never appears
    assert key not in json.dumps(data)
    # masked prefix includes beginning plus ellipsis and hash suffix
    assert data["key_prefix"].startswith("AbCdEfGh…")
    assert len(data["key_prefix"]) > len("AbCdEfGh…")  # has hash suffix

    # non-PII operational fields are preserved
    assert data["tenant"] == "t-1"
    assert data["fp_prefix"] == "deadbeef"
    assert data["replay_count"] == 3
    assert data["privacy_mode"] == "pii_disabled"

    # headers dropped when PII disabled
    assert "headers" not in data


def test_masking_with_pii(caplog, monkeypatch):
    monkeypatch.setenv("IDEMP_LOG_INCLUDE_PII", "1")
    caplog.set_level("INFO", logger="app.idempotency")

    key = "XYZ987654321"
    log_idempotency_event(
        "leader_acquired",
        idempotency_key=key,
        tenant="t-2",
        headers={"authorization": "secret"},
    )

    data = _last_json_record(caplog)

    # still never log full key even if PII enabled
    assert key not in json.dumps(data)
    assert data["key_prefix"].startswith("XYZ98765…")
    assert data["privacy_mode"] == "pii_enabled"

    # headers present when PII enabled
    assert "headers" in data


def test_masking_short_keys_never_full(caplog, monkeypatch):
    monkeypatch.setenv("IDEMP_LOG_INCLUDE_PII", "0")
    caplog.set_level("INFO", logger="app.idempotency")

    # very short keys must not appear verbatim
    for key in ("a", "ab", "abc"):
        log_idempotency_event("replay", key=key)
        data = _last_json_record(caplog)
        masked = data["key_prefix"]
        assert key not in masked
        # always contains ellipsis and some suffix
        assert "…" in masked
        assert len(masked.split("…")[-1]) >= 1
