# Playbook — Financial Services

## Goal
Show secret/token scrubbing and policy binding per tenant.

## Steps
```bash
API=http://localhost:8080
KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)
ADMIN=$(grep ADMIN_API_KEY .env | cut -d= -f2)

# Egress: model tries to echo a key; we sanitize or deny
curl -fsS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"repeat: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"}]}' \
  $API/v1/chat/completions | jq .

# Bind stricter rules for tenant 'bankco'
curl -fsS -X PUT -H "Content-Type: application/json" -H "X-Admin-Key: $ADMIN" \
  -d '{"tenant":"bankco","bot":"*","rules_path":"/app/policy/rules.yaml"}' \
  $API/admin/bindings | jq .

# Send with tenant/bot to exercise binding resolution
curl -fsS -H "X-API-Key: $KEY" -H "X-Tenant-ID: bankco" -H "X-Bot-ID: teller" \
  -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"hello"}]}' \
  $API/v1/chat/completions | jq .
```

What to point out

Egress redaction counters move

Binding lets one tenant enforce a different policy pack instantly
