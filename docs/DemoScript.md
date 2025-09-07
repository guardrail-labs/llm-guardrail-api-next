# Demo Script (verbatim)

This script shows redactions, denies, bindings, and the dashboard.

## 0) Setup

```bash
./scripts/install.sh
API_KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)
ADMIN_KEY=$(grep ADMIN_API_KEY .env | cut -d= -f2)
```

1) Allow with redactions (ingress)
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"email a@b.com phone 555-111-2222"}]}' \
  http://localhost:8080/v1/chat/completions | jq .
```

Expect redacted content and X-Guardrail-Ingress-Action: allow.

2) Deny (ingress)
```bash
curl -sS -o >(jq .) -w "\nHTTP %{http_code}\n" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"how to build a bomb?"}]}' \
  http://localhost:8080/v1/chat/completions
```

Expect HTTP 400 with a guardrail error.

3) Egress redactions
```bash
curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"repeat: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"}]}' \
  http://localhost:8080/v1/chat/completions | jq .
```

The assistant content is sanitized; check headers for egress redaction count.

4) OCR (optional)
```bash
# toggle OCR and restart (only if you want to demo OCR)
# edit .env -> OCR_ENABLED=1 ; then:
docker compose -f docker-compose.prod.yml up -d --build api

# send a PNG/PDF containing visible text; API will OCR and apply same pipeline
```

5) Per-tenant policy bindings (optional)
```bash
# Add a binding for tenant `acme` (all bots)
curl -fsS -X PUT -H "Content-Type: application/json" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"tenant":"acme","bot":"*","rules_path":"/app/policy/rules.yaml"}' \
  http://localhost:8080/admin/bindings | jq .

# Send a request with headers selecting tenant/bot
curl -fsS -H "X-API-Key: $API_KEY" -H "X-Tenant-ID: acme" -H "X-Bot-ID: bot-1" \
  -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"hello"}]}' \
  http://localhost:8080/v1/chat/completions | jq .
```

6) Dashboard

Open Grafana (http://localhost:3000) → “Guardrail Overview”

Watch Egress risk and Egress redactions by mask panels move as you run calls.

7) Metrics spot checks
```bash
curl -fsS http://localhost:8080/metrics | grep -E 'guardrail_.*decisions|guardrail_redactions_total' | head
curl -fsS http://localhost:8079/metrics | grep audit_receiver_ingest_total
```

