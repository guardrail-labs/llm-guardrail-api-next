from __future__ import annotations

import threading

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.routes import admin_decisions


def _make_request() -> Request:
    scope = {"type": "http", "headers": [], "query_string": b"", "method": "GET"}
    return Request(scope)


def test_stream_decisions_subscribe_failure_decrements(monkeypatch):
    monkeypatch.setattr(admin_decisions, "_CLIENTS", 0, raising=False)
    monkeypatch.setattr(admin_decisions, "_CLIENTS_LOCK", threading.Lock(), raising=False)

    def boom():
        raise RuntimeError("subscribe failed")

    monkeypatch.setattr(admin_decisions, "subscribe", boom)

    with pytest.raises(HTTPException) as exc:
        admin_decisions.stream_decisions(_make_request(), None)

    assert exc.value.status_code == 503
    assert admin_decisions._CLIENTS == 0
