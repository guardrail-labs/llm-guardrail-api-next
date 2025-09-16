from __future__ import annotations

import types
from typing import Any

import pytest

import app.services.webhooks as wh


class _FakeReg:
    def __init__(self) -> None:
        self._open = False
        self.calls = {"should": 0, "succ": 0, "fail": 0}

    def should_dlq_now(self, url: str) -> bool:
        self.calls["should"] += 1
        return self._open

    def on_success(self, url: str) -> None:
        self.calls["succ"] += 1
        self._open = False

    def on_failure(self, url: str) -> None:
        self.calls["fail"] += 1
        self._open = True


def test_cb_rechecked_each_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _FakeReg()

    monkeypatch.setattr(wh, "get_cb_registry", lambda: reg)
    monkeypatch.setattr(
        wh,
        "get_config",
        lambda: {
            "webhook_url": "https://dead.example.com/hook",
            "webhook_secret": "",
            "webhook_timeout_ms": 200,
            "webhook_max_retries": 3,
            "webhook_backoff_ms": 50,
            "webhook_allow_insecure_tls": True,
            "webhook_allowlist_host": "dead.example.com",
        },
    )

    attempts = {"count": 0}

    class _FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def post(
            self,
            url: str,
            content: bytes | None = None,
            headers: dict[str, str] | None = None,
        ) -> types.SimpleNamespace:
            attempts["count"] += 1
            return types.SimpleNamespace(status_code=500)

    monkeypatch.setattr(wh.httpx, "Client", _FakeClient)

    dlq: dict[str, Any] = {"count": 0, "reasons": []}

    def _fake_dlq_write(evt: dict[str, Any], *, reason: str) -> None:
        dlq["count"] += 1
        dlq["reasons"].append(reason)

    monkeypatch.setattr(wh, "_dlq_write", _fake_dlq_write)
    monkeypatch.setattr(wh.time, "sleep", lambda _: None)

    outcome, status = wh._deliver({"incident_id": "cb", "request_id": "cb"})

    assert attempts["count"] == 1
    assert outcome == "cb_open" and status == "-"
    assert dlq["count"] == 1
    assert dlq["reasons"] == ["cb_open"]
    assert reg.calls["fail"] >= 1
    assert reg.calls["should"] >= 2
