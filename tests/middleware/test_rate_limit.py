from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Set

from fastapi import FastAPI
from starlette.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware
from app.services import ratelimit as rl

_EXPECTED_KEYS: Set[str] = {
    "X-Quota-Day",
    "X-Quota-Hour",
    "X-Quota-Min",
    "X-Quota-Remaining",
    "X-Quota-Reset",
}

_HEADERS = {"X-Guardrail-Tenant": "acme", "X-Guardrail-Bot": "web"}


@contextmanager
def _client(monkeypatch, *, rps: float, burst: float) -> Iterator[TestClient]:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", str(rps))
    monkeypatch.setenv("RATE_LIMIT_BURST", str(burst))
    monkeypatch.setenv("RATE_LIMIT_ENFORCE_UNKNOWN", "true")
    monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
    monkeypatch.setattr(rl, "_global_limiter", None, raising=False)

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        yield client


def test_headers_present_on_allow(monkeypatch) -> None:
    with _client(monkeypatch, rps=5.0, burst=5.0) as client:
        resp = client.get("/ping", headers=_HEADERS)
        assert resp.status_code == 200

        have = {k.title() for k in resp.headers if k.lower().startswith("x-quota-")}
        assert have == _EXPECTED_KEYS

        reset = resp.headers["X-Quota-Reset"]
        assert reset.isdigit()


def test_headers_present_on_deny(monkeypatch) -> None:
    with _client(monkeypatch, rps=1.0, burst=1.0) as client:
        resp = client.get("/ping", headers=_HEADERS)
        for _ in range(100):
            if resp.status_code == 429:
                break
            resp = client.get("/ping", headers=_HEADERS)
        assert resp.status_code == 429

        have = {k.title() for k in resp.headers if k.lower().startswith("x-quota-")}
        assert have == _EXPECTED_KEYS

        reset = resp.headers["X-Quota-Reset"]
        assert reset.isdigit()


def test_identical_sets_between_allow_and_deny(monkeypatch) -> None:
    with _client(monkeypatch, rps=1.0, burst=1.0) as client:
        allow_resp = client.get("/ping", headers=_HEADERS)
        assert allow_resp.status_code == 200
        allow_keys = {k.title() for k in allow_resp.headers if k.lower().startswith("x-quota-")}

        deny_resp = allow_resp
        for _ in range(100):
            deny_resp = client.get("/ping", headers=_HEADERS)
            if deny_resp.status_code == 429:
                break
        assert deny_resp.status_code == 429
        deny_keys = {k.title() for k in deny_resp.headers if k.lower().startswith("x-quota-")}

        assert allow_keys == deny_keys == _EXPECTED_KEYS
