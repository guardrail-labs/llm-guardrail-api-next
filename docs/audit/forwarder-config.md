# Forwarder configuration (your app)

| Variable                      | Required | Default | Purpose |
|------------------------------|----------|---------|---------|
| `AUDIT_FORWARD_ENABLED`      | yes      | `false` | If `1/true`, send events. |
| `AUDIT_FORWARD_URL`          | yes      | —       | Receiver URL (e.g. `https://audit.example.com/audit`). |
| `AUDIT_FORWARD_API_KEY`      | yes      | —       | Shared API key header. |
| `AUDIT_FORWARD_SIGNING_SECRET`| yes     | —       | HMAC secret for request signing. |
| `AUDIT_FORWARD_RETRIES`      | no       | `3`     | Retry attempts on failure. |
| `AUDIT_FORWARD_BACKOFF_MS`   | no       | `100`   | Linear backoff base in ms. |
| `APP_NAME`                   | no       | `llm-guardrail-api` | Tagged into the event as `service`. |
| `ENV` / `APP_ENV`            | no       | —       | Tagged into the event as `env`. |

### Programmatic usage

```py
from app.services.audit import emit_audit_event

emit_audit_event({
  "event": "prompt_decision",
  "direction": "ingress",
  "decision": "allow",
  "tenant_id": "default",
  "bot_id": "default",
  "rule_hits": ["secrets:*"] ,
  "redaction_count": 1,
  # ts/request_id/policy_version/service/env normalized automatically
})
```
