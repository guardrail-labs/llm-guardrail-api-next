from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.audit.exporter import bundle_to_csv, make_bundle
from app.audit.models import AuditStore
from app.security.rbac import require_admin

router = APIRouter(prefix="/admin/audit", tags=["admin:audit"])


def get_audit_store() -> AuditStore:
    raise HTTPException(status_code=501, detail="Audit store not configured")


@router.get("/export", dependencies=[Depends(require_admin)])
def export_audit(
    tenant: str = Query(..., min_length=1),
    incident_id: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    fmt: str = Query("json", pattern="^(json|csv)$"),
    store: AuditStore = Depends(get_audit_store),
) -> Any:
    rows = store.query(
        tenant=tenant,
        start_iso=start,
        end_iso=end,
        incident_id=incident_id,
        limit=10_000,
    )
    bundle = make_bundle(tenant, rows)
    if fmt == "csv":
        csv_text = bundle_to_csv(bundle)
        return Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=bundle.csv"},
        )
    return bundle
