from __future__ import annotations

import os

from starlette.testclient import TestClient

from app.main import create_app


def _mk_app(per_day: int = 2, per_month: int = 5):
    os.environ["QUOTA_ENABLED"] = "true"
    os.environ["QUOTA_PER_DAY"] = str(per_day)
    os.environ["QUOTA_PER_MONTH"] = str(per_month)
    return create_app()


def test_status_reflects_usage_and_limits():
    app = _mk_app(per_day=2, per_month=5)
    c = TestClient(app)
    h = {"x-api-key": "K-ADMIN-1"}

    # consume one
    r = c.get("/health", headers=h)
    assert r.status_code == 200

    s = c.get("/admin/quota/status", params={"key": "K-ADMIN-1"})
    assert s.status_code == 200
    body = s.json()
    assert body["enabled"] is True
    assert body["limits"]["per_day"] == 2
    assert body["limits"]["per_month"] == 5
    # one used -> remaining day 1, month 4
    assert body["status"]["day_remaining"] == 1
    assert body["status"]["month_remaining"] == 4
    assert body["status"]["reset_earliest_s"] >= 1


def test_reset_day_clears_day_window_only():
    app = _mk_app(per_day=3, per_month=5)
    c = TestClient(app)
    h = {"x-api-key": "K-ADMIN-2"}

    # consume two
    assert c.get("/health", headers=h).status_code == 200
    assert c.get("/health", headers=h).status_code == 200

    s1 = c.get("/admin/quota/status", params={"key": "K-ADMIN-2"}).json()
    assert s1["status"]["day_remaining"] == 1
    assert s1["status"]["month_remaining"] == 3

    r = c.post("/admin/quota/reset", json={"key": "K-ADMIN-2", "scope": "day"})
    assert r.status_code == 200

    s2 = c.get("/admin/quota/status", params={"key": "K-ADMIN-2"}).json()
    # day window reset -> full; month remains reduced
    assert s2["status"]["day_remaining"] == 3
    assert s2["status"]["month_remaining"] == 3


def test_missing_key_returns_400():
    app = _mk_app()
    c = TestClient(app)
    r = c.get("/admin/quota/status")
    assert r.status_code in {400, 422}  # FastAPI may 422 for missing required query

