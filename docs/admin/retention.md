# Admin retention cleanup APIs

The admin API exposes helpers to preview and prune historical guardrail data. Both endpoints
require an authenticated admin session. Mutating calls must include a CSRF token (cookie + header
or explicit override) and the JSON body confirmation string `"DELETE"`.

## Preview

`POST /admin/api/retention/preview`

```json
{
  "before_ts_ms": 1700000000000,
  "tenant": "acme",
  "bot": "chat-bot"
}
```

The response returns the number of decisions and adjudications older than the cutoff. Filters are
optional – omit `tenant` and/or `bot` to operate across the entire dataset.

## Execute

`POST /admin/api/retention/execute`

Body fields:

- `before_ts_ms` – timestamp (exclusive) in epoch milliseconds.
- `tenant`, `bot` – optional filters to scope the delete.
- `confirm` – must be exactly `DELETE`.
- `csrf_token` – must be present and match the UI token.
- `max_delete` – optional bound (default 50k) across decisions + adjudications.

The endpoint deletes up to `max_delete` records (decisions first, adjudications second) and returns
per-kind deletion counts. Metrics are exposed via Prometheus:

- `guardrail_retention_preview_total`
- `guardrail_retention_deleted_total{kind="decisions|adjudications"}`

Each execution emits an audit event `admin.retention.execute` including the actor, cutoff and delete
counts. Coordinate large deletions with downstream teams consuming audit or decisions data.
