from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.quota import QuotaMiddleware
from app.services.quota.store import FixedWindowQuotaStore
from app.shared.headers import BOT_HEADER, TENANT_HEADER


def _fixed_time(epoch: int):
    class _Now:
        def __call__(self) -> float:
            return float(epoch)

    return _Now()


def _app(
    per_day: int = 2,
    per_month: int = 10,
    *,
    emit_calls: List[Dict[str, Any]] | None = None,
    metric_calls: List[tuple[str, str]] | None = None,
) -> FastAPI:
    app = FastAPI()
    t0 = int(dt.datetime(2025, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp())
    store = FixedWindowQuotaStore(per_day=per_day, per_month=per_month, now_fn=_fixed_time(t0))

    # Subclass to inject test store
    class _TestQuota(QuotaMiddleware):
        def __init__(self, app):
            super().__init__(app, enabled=True, per_day=per_day, per_month=per_month)
            self.store = store  # inject deterministic store

    app.add_middleware(_TestQuota)

    # Patch audit + metrics at app scope so we can import-free monkeypatching via closure
    import app.middleware.quota as qm
    if emit_calls is not None:
        def _emit(evt: Dict[str, Any]) -> None:
            emit_calls.append(evt)

        qm.emit_audit_event = _emit  # type: ignore[assignment]
    if metric_calls is not None:
        def _inc(tenant: str, bot: str) -> None:
            metric_calls.append((tenant, bot))

        qm.inc_quota_reject_tenant_bot = _inc

    @app.get("/ok")
    def ok() -> PlainTextResponse:
        return PlainTextResponse("ok")

    return app


def test_tenant_bot_quota_allows_then_429_with_audit_and_metrics():
    emits: List[Dict[str, Any]] = []
    metrics: List[tuple[str, str]] = []
    app = _app(per_day=2, per_month=1000, emit_calls=emits, metric_calls=metrics)
    c = TestClient(app)
    h = {TENANT_HEADER: "T1", BOT_HEADER: "B1"}

    r1 = c.get("/ok", headers=h)
    assert r1.status_code == 200
    assert int(r1.headers["X-Quota-Remaining-Day"]) == 1

    r2 = c.get("/ok", headers=h)
    assert r2.status_code == 200
    assert int(r2.headers["X-Quota-Remaining-Day"]) == 0

    r3 = c.get("/ok", headers=h)
    assert r3.status_code == 429
    j = r3.json()
    assert j["code"] == "quota_exhausted"
    assert "retry_after_seconds" in j
    assert r3.headers.get("Retry-After") is not None

    # metrics + audit emitted once
    assert metrics == [("T1", "B1")]
    assert len(emits) == 1
    evt = emits[0]
    assert evt.get("tenant_id") == "T1"
    assert evt.get("bot_id") == "B1"
    assert evt.get("status_code") == 429
    assert evt.get("decision") == "deny"
    assert evt.get("policy_version")


def test_quota_isolated_by_tenant_and_bot():
    app = _app(per_day=1, per_month=1000)
    c = TestClient(app)
    h1 = {TENANT_HEADER: "ACME", BOT_HEADER: "chat"}
    h2 = {TENANT_HEADER: "ACME", BOT_HEADER: "emb"}
    h3 = {TENANT_HEADER: "OTHER", BOT_HEADER: "chat"}

    assert c.get("/ok", headers=h1).status_code == 200
    assert c.get("/ok", headers=h1).status_code == 429  # ACME:chat exhausted

    # Different bot under same tenant is independent
    assert c.get("/ok", headers=h2).status_code == 200

    # Different tenant is independent
    assert c.get("/ok", headers=h3).status_code == 200


def test_month_quota_blocks_when_day_has_room():
    app = _app(per_day=1000, per_month=1)
    c = TestClient(app)
    h = {TENANT_HEADER: "T", BOT_HEADER: "B"}

    assert c.get("/ok", headers=h).status_code == 200
    r2 = c.get("/ok", headers=h)
    assert r2.status_code == 429
    assert "month" in r2.json()["detail"].lower()

