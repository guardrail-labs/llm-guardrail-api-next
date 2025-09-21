import types
from typing import List, Tuple

import pytest
from fastapi.testclient import TestClient


class _CounterStub:
    def __init__(self) -> None:
        self.increments: List[int] = []

    def inc(self, value: int = 1) -> None:
        self.increments.append(value)


class _FakeDLQ:
    def __init__(self) -> None:
        self.items: List[Tuple[int, str]] = []

    def push(self, ts_ms: int, error: str) -> None:
        self.items.append((ts_ms, error))

    def stats(self) -> dict:
        if not self.items:
            return {
                "size": 0,
                "oldest_ts_ms": None,
                "newest_ts_ms": None,
                "last_error": None,
            }
        size = len(self.items)
        oldest = min(ts for ts, _ in self.items)
        newest = max(ts for ts, _ in self.items)
        last_error = self.items[-1][1]
        return {
            "size": size,
            "oldest_ts_ms": oldest,
            "newest_ts_ms": newest,
            "last_error": last_error,
        }

    def retry_all(self) -> int:
        count = len(self.items)
        self.items.clear()
        return count

    def purge_all(self) -> int:
        count = len(self.items)
        self.items.clear()
        return count


@pytest.fixture()
def _patched_dlq(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeDLQ()
    counters = {
        "retry": _CounterStub(),
        "purge": _CounterStub(),
    }
    events: List[dict] = []

    import app.routes.admin_webhooks_dlq as dlq_route

    monkeypatch.setattr(
        dlq_route,
        "DLQ",
        types.SimpleNamespace(
            stats=fake.stats,
            retry_all=fake.retry_all,
            purge_all=fake.purge_all,
        ),
    )
    monkeypatch.setattr(dlq_route, "webhook_dlq_retry_total", counters["retry"])
    monkeypatch.setattr(dlq_route, "webhook_dlq_purge_total", counters["purge"])
    monkeypatch.setattr(dlq_route, "emit_audit_event", lambda event: events.append(event))
    monkeypatch.setattr(dlq_route, "_require_ui_csrf", lambda request, token: None)
    monkeypatch.setattr(dlq_route, "require_admin_session", lambda request: None)

    return fake, counters, events


@pytest.fixture()
def app_factory(_patched_dlq):
    from app.main import create_app

    def factory():
        return create_app()

    return factory


def _client(app_factory):
    app = app_factory()
    return TestClient(app)


def test_dlq_stats_empty(app_factory):
    c = _client(app_factory)
    r = c.get("/admin/api/webhooks/dlq")
    assert r.status_code == 200
    assert r.json()["size"] == 0


def test_dlq_retry_and_purge(_patched_dlq, app_factory):
    fake, counters, events = _patched_dlq
    fake.push(1710000000000, "timeout")
    fake.push(1710000001000, "5xx")

    c = _client(app_factory)
    headers = {"X-Admin-Actor": "tester", "X-Request-ID": "req-123"}

    r = c.post("/admin/api/webhooks/dlq/retry", json={"csrf_token": "ok"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["requeued"] == 2
    assert fake.stats()["size"] == 0
    assert counters["retry"].increments == [2]
    assert events[0]["action"].endswith(".retry")
    assert events[0]["actor"] == "tester"
    assert events[0]["request_id"] == "req-123"

    r2 = c.post("/admin/api/webhooks/dlq/purge", json={"csrf_token": "ok"}, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["deleted"] == 0
    assert counters["purge"].increments == [0]
    assert events[-1]["action"].endswith(".purge")
    assert events[-1]["count"] == 0
