from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.testclient import TestClient

from app.audit.models import AuditRecord, AuditStore
from app.routes.admin_audit import get_audit_store, router as audit_router
from app.security.rbac import require_admin


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
    def _allow(_: Request) -> Dict[str, str]:
        return {"email": "tester@example.com", "role": "admin"}

    app.dependency_overrides[require_admin] = _allow
    return app


def _app_with_auth(rows: List[AuditRecord]) -> FastAPI:
    app = FastAPI()
    app.include_router(audit_router)
    app.dependency_overrides[get_audit_store] = lambda: _FakeStore(rows)

    async def _guard(x_admin: str | None = Header(default=None)) -> None:
        if x_admin != "1":
            raise HTTPException(status_code=403, detail="admin required")

    app.dependency_overrides[require_admin] = _guard
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


def test_export_requires_admin_auth() -> None:
    rows = [_rec("allow", "allow", None)]
    app = _app_with_auth(rows)
    client = TestClient(app)

    unauth = client.get("/admin/audit/export", params={"tenant": "acme"})
    assert unauth.status_code == 403

    auth = client.get(
        "/admin/audit/export",
        params={"tenant": "acme"},
        headers={"x-admin": "1"},
    )
    assert auth.status_code == 200
    body = auth.json()
    assert body["tenant"] == "acme"
    assert body["count"] == 1
