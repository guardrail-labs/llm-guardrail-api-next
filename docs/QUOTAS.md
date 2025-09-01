# Per-Tenant/Bot Quotas

Quotas run **pre-ingress** on all OpenAI/Azure endpoints. A single unit is consumed per request (stream, non-stream, images, embeddings, moderations).

## Modes

- **Hard**: exceed -> HTTP 429 with `Retry-After` and audit.
- **Soft**: exceed -> *allowed*, still counted; useful for alerting only.

## Config (env or app.state)

Environment (defaults shown):


QUOTA_ENABLED=false
QUOTA_MODE=hard # hard|soft
QUOTA_PER_MINUTE=0 # 0 disables cap
QUOTA_PER_DAY=0 # 0 disables cap


Per-app overrides (tests/demos):
```python
app.state.quota_enabled = True
app.state.quota_mode = "hard"
app.state.quota_per_minute = 60
app.state.quota_per_day = 5000
```

Behavior

On exceed (hard):

429 with JSON body:

{
  "code": "rate_limited",
  "detail": "Per-tenant quota exceeded",
  "retry_after": 60,
  "request_id": "..."
}


Headers: Retry-After, X-Guardrail-*

Audit event (decision: "deny", status_code: 429)

Prometheus: guardrail_quota_rejects_total{tenant_id,bot_id} increments

On exceed (soft):

Request proceeds; no 429

Still emits audits and is visible in metrics

Tenancy

Quotas key by (tenant_id, bot_id) using headers:

X-Tenant-ID

X-Bot-ID
Defaults to "default" when missing.

Reset (tests)
```python
from app.services.quotas import reset_quota_state
reset_quota_state()
```
