from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from app.audit.models import AuditRecord
from app.audit.redact import redact_obj


def make_bundle(tenant: str, records: Iterable[AuditRecord]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for record in records:
        rows.append(
            {
                "ts": record.ts,
                "tenant": tenant,
                "request_id": record.request_id,
                "incident_id": record.incident_id,
                "decision": record.decision,
                "mode": record.mode,
                "headers": redact_obj(record.headers),
                "payload": redact_obj(record.payload),
            }
        )
    return {
        "tenant": tenant,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "records": rows,
    }


def bundle_to_csv(bundle: Dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "ts",
            "tenant",
            "request_id",
            "incident_id",
            "decision",
            "mode",
            "headers_json",
            "payload_json",
        ]
    )
    for record in bundle.get("records", []):
        writer.writerow(
            [
                record.get("ts", ""),
                record.get("tenant", ""),
                record.get("request_id", ""),
                record.get("incident_id", "") or "",
                record.get("decision", ""),
                record.get("mode", ""),
                json.dumps(record.get("headers", {}), ensure_ascii=False),
                json.dumps(record.get("payload", {}), ensure_ascii=False),
            ]
        )
    return buffer.getvalue()
