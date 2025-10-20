from __future__ import annotations

from typing import List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.models import AuditRecord, AuditStore
from app.routes.admin_audit import get_audit_store, router as audit_router


class _FakeStore(AuditStore):
    def __init__(self, rows: List[AuditRecord]) -> None:
        self._rows = rows

    def query(
        self,
        tenant: str,
        start_iso: Optional[str] = None,
        end_iso: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 10_000,
    ) -> List[AuditRecord]:
        records = [row for row in self._rows if row.tenant == tenant]
        if incident_id:
            records = [row for row in records if row.incident_id == incident_id]
        return records[:limit]


def _app_with(rows: List[AuditRecord]) -> FastAPI:
    app = FastAPI()
    app.include_router(audit_router)
    app.dependency_overrides[get_audit_store] = lambda: _FakeStore(rows)
    return app


def _rec(decision: str, mode: str, incident: Optional[str]) -> AuditRecord:
    return AuditRecord(
        ts="2025-10-20T10:00:00Z",
        tenant="acme",
        request_id="req-123",
        incident_id=incident,
        decision=decision,
        mode=mode,
        headers={
            "authorization": "Bearer abc",
            "x-user": "alice@example.com",
        },
        payload={"ssn": "123-45-6789", "note": "call 555-111-2222"},
    )


def test_json_bundle_redacts_and_filters_by_incident() -> None:
    rows = [
        _rec("allow", "allow", None),
        _rec("block-input", "block_input", "inc-1"),
    ]
    app = _app_with(rows)
    client = TestClient(app)

    response = client.get(
        "/admin/audit/export",
        params={"tenant": "acme", "incident_id": "inc-1", "fmt": "json"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["tenant"] == "acme"
    assert data["count"] == 1
    record = data["records"][0]
    assert record["headers"]["authorization"] == "[REDACTED]"
    assert record["headers"]["x-user"] == "[REDACTED]"
    assert record["payload"]["ssn"] == "[REDACTED]"
    assert "[REDACTED]" in record["payload"]["note"]


def test_csv_bundle_download() -> None:
    rows = [_rec("clarify", "clarify", "inc-2")]
    app = _app_with(rows)
    client = TestClient(app)
    response = client.get(
        "/admin/audit/export",
        params={"tenant": "acme", "fmt": "csv"},
    )
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"].lower()
    assert "ts,tenant,request_id,incident_id" in response.text.splitlines()[0]
