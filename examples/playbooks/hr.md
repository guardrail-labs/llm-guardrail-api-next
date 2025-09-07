# Playbook — HR Assistant (PII hygiene)

## Goal
Show that employee PII is redacted at ingress and reflected in dashboards.

## Steps
```bash
API=http://localhost:8080
KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)

# Email/phone redacted (ingress allow + redactions)
curl -fsS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"Contact Jane: jane.doe@corp.example, 555-222-3333"}]}' \
  $API/v1/chat/completions | jq .

# Metrics spot check
curl -fsS $API/metrics | grep -E 'guardrail_decisions_family_.*allow|guardrail_redactions_total'
```

What to point out

Response shows [REDACTED:EMAIL], [REDACTED:PHONE]

Grafana panel “Egress redactions by mask” updates after a few requests
