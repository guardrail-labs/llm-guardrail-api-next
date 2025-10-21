from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.services.dlq import DLQMessage


class FakeDLQService:
    def __init__(self) -> None:
        self.pending_messages: List[DLQMessage] = []
        self.quarantine_ids: List[str] = []
        self.replay_map: Dict[str, DLQMessage] = {}
        self.ack_ids: set[str] = set()
        self.list_pending_calls: List[tuple[str, str, int]] = []
        self.list_quarantine_calls: List[tuple[str, str, int]] = []
        self.replay_requests: List[str] = []
        self.ack_requests: List[str] = []

    async def list_pending(self, tenant: str, topic: str, limit: int = 100) -> List[DLQMessage]:
        self.list_pending_calls.append((tenant, topic, limit))
        return self.pending_messages[:limit]

    async def list_quarantine(self, tenant: str, topic: str, limit: int = 200) -> List[str]:
        self.list_quarantine_calls.append((tenant, topic, limit))
        return self.quarantine_ids[:limit]

    async def replay_now(self, msg_id: str) -> DLQMessage | None:
        self.replay_requests.append(msg_id)
        return self.replay_map.get(msg_id)

    async def ack(self, msg_id: str) -> bool:
        self.ack_requests.append(msg_id)
        return msg_id in self.ack_ids


def _make_message(msg_id: str, **overrides: Any) -> DLQMessage:
    base = {
        "id": msg_id,
        "tenant": overrides.get("tenant", "tenant-a"),
        "topic": overrides.get("topic", "topic-x"),
        "payload": overrides.get("payload", {"x": 1}),
        "tries": overrides.get("tries", 0),
        "created_ts": overrides.get("created_ts", 10.0),
        "first_failure_ts": overrides.get("first_failure_ts", 10.0),
        "last_attempt_ts": overrides.get("last_attempt_ts"),
        "next_attempt_ts": overrides.get("next_attempt_ts", 20.0),
        "last_error": overrides.get("last_error"),
    }
    return DLQMessage(**base)


@pytest.fixture()
def fake_dlq_service() -> FakeDLQService:
    return FakeDLQService()


@pytest.fixture()
def client(fake_dlq_service: FakeDLQService) -> TestClient:
    from app.main import create_app
    from app.routes import admin_rbac, admin_ui, admin_webhook_replay as replay_route
    from app.runtime import get_dlq_service

    app = create_app()

    def _allow(_: Request) -> None:
        return None

    app.dependency_overrides[admin_rbac.require_admin] = _allow
    app.dependency_overrides[admin_ui.require_auth] = _allow
    app.dependency_overrides[replay_route.require_admin] = _allow
    app.dependency_overrides[replay_route.require_auth] = _allow
    app.dependency_overrides[get_dlq_service] = lambda: fake_dlq_service

    return TestClient(app)


def test_quarantine_listing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    fake_dlq_service.quarantine_ids = ["m1", "m2", "m3"]

    response = client.get(
        "/admin/webhooks/dlq/quarantine",
        params={"tenant": "tenant-a", "topic": "topic-x", "limit": 2},
    )

    assert response.status_code == 200
    assert response.json()["ids"] == ["m1", "m2"]
    assert fake_dlq_service.list_quarantine_calls == [("tenant-a", "topic-x", 2)]


def test_pending_listing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    message = _make_message("p1", tries=3, next_attempt_ts=42.5, last_error="boom")
    fake_dlq_service.pending_messages = [message]

    response = client.get(
        "/admin/webhooks/dlq/pending",
        params={"tenant": "tenant-a", "topic": "topic-x"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["messages"]) == 1
    item = body["messages"][0]
    assert item["id"] == "p1"
    assert item["tries"] == 3
    assert item["next_attempt_ts"] == pytest.approx(42.5)
    assert item["last_error"] == "boom"
    assert fake_dlq_service.list_pending_calls == [("tenant-a", "topic-x", 100)]


def test_replay_existing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    message = _make_message("abc", next_attempt_ts=88.2)
    fake_dlq_service.replay_map["abc"] = message

    response = client.post("/admin/webhooks/dlq/abc/replay")

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == "abc"
    assert payload["next_attempt_ts"] == pytest.approx(88.2)
    assert fake_dlq_service.replay_requests == ["abc"]


def test_replay_missing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    response = client.post("/admin/webhooks/dlq/missing/replay")

    assert response.status_code == 404
    assert response.json()["detail"] == "message not found"
    assert fake_dlq_service.replay_requests == ["missing"]


def test_delete_existing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    fake_dlq_service.ack_ids.add("gone")

    response = client.delete("/admin/webhooks/dlq/gone")

    assert response.status_code == 200
    assert response.json()["status"] == "deleted"
    assert fake_dlq_service.ack_requests == ["gone"]


def test_delete_missing(client: TestClient, fake_dlq_service: FakeDLQService) -> None:
    response = client.delete("/admin/webhooks/dlq/not-there")

    assert response.status_code == 404
    assert response.json()["detail"] == "message not found"
    assert fake_dlq_service.ack_requests == ["not-there"]
