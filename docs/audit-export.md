# Audit Export (Core)

**Route:** `GET /admin/audit/export`

**Query params**
- `tenant` (required)
- `incident_id` (optional)
- `start`, `end` (ISO 8601, optional)
- `fmt` = `json` | `csv` (default `json`)

**JSON bundle schema**
```json
{
  "tenant": "acme",
  "generated_at": "2025-10-20T10:21:00.000Z",
  "count": 42,
  "records": [
    {
      "ts": "2025-10-20T10:00:00Z",
      "request_id": "req-123",
      "incident_id": "inc-1",
      "decision": "block-input",
      "mode": "block_input",
      "headers": { "...": "[REDACTED]" },
      "payload": { "...": "[REDACTED]" }
    }
  ]
}
```

Redaction masks emails, SSNs, and phone numbers in strings.

Keys named api_key, authorization, token, secret, or password are masked.

## CLI

```bash
python -m cli.audit_export \
  --base-url http://localhost:8000 \
  --tenant acme \
  --incident-id inc-1 \
  --outdir audit_exports
```

---

**Wire-up hint (for your app)**

```python
from app.routes.admin_audit import router as audit_router, get_audit_store
from app.audit.models import AuditStore

class MyAuditStore(AuditStore):
    ...  # implement .query()

app.include_router(audit_router)
app.dependency_overrides[get_audit_store] = lambda: MyAuditStore(...)
```

## Local run

```bash
ruff check .
mypy .
pytest -q
```
