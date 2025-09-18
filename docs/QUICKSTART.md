# Guardrail API — Quickstart (Core)

This gets you from zero → working core in minutes.

## 0) Prereqs
- Docker & Docker Compose
- `curl`, `jq`

## 1) Boot the stack
```bash
docker compose up --build -d
```

## 2) Set admin key (shell env)
```bash
export ADMIN_KEY="dev-admin-key"
```

If running via Compose-provided env, keep this in sync with `ADMIN_API_KEY`.

## 3) Verify health
```bash
curl -sS localhost:8080/readyz | jq .
curl -sS localhost:8080/livez  | jq .
```

## 4) Apply golden packs (PII + Secrets)

List packs:
```bash
curl -sS -H "X-Admin-Key: $ADMIN_KEY" localhost:8080/admin/api/policy/packs | jq .
```

Bind packs to a demo tenant/bot:
```bash
curl -sS -X PUT -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  localhost:8080/admin/bindings -d '{
  "bindings": [
    {"tenant":"demo","bot":"site","rules_path":"pii_redact"},
    {"tenant":"demo","bot":"site","rules_path":"secrets_redact"}
  ]
}' | jq .
```

## 5) Validate & reload policy
```bash
CSRF=$(openssl rand -hex 16 2>/dev/null || uuidgen 2>/dev/null || date +%s)
curl -sS -X POST \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -H "Cookie: csrf=$CSRF" \
  -H "X-CSRF-Token: $CSRF" \
  -d "{\"csrf_token\":\"$CSRF\"}" \
  localhost:8080/admin/api/policy/reload | jq .
```

## 6) Prove redaction end-to-end

Send demo content through the admin echo endpoint (redaction middleware applies to its response):
```bash
curl -sS -G \
  -H "X-Admin-Key: $ADMIN_KEY" \
  --data-urlencode "text=Email a.b+z@example.co.uk, JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy" \
  localhost:8080/admin/echo
```

Expected: email/JWT are redacted and response contains `X-Redaction-Mode: windowed` (or skip headers if streaming).

## 7) See decisions & export
```bash
curl -sS -H "X-Admin-Key: $ADMIN_KEY" \
  "localhost:8080/admin/api/decisions?since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | jq .

# Export NDJSON
curl -sS -H "X-Admin-Key: $ADMIN_KEY" \
  "localhost:8080/admin/api/decisions/export.ndjson?since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | head
```

## 8) Dashboards

Open Grafana → Guardrail Core dashboard. Check:

- Outcomes by type
- Egress redaction stats
- Rate-limit counters
- DLQ panels (if webhooks used)

## 9) Next steps

- Tune packs in `policies/packs/` (or `policy/packs/`); validate in Admin UI.
- Flip `POLICY_VALIDATE_ENFORCE=block` in prod.
