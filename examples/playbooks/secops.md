# Playbook — Security Operations

## Goal
Prove we block private key envelopes and show it in egress metrics.

## Steps
```bash
API=http://localhost:8080
KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)

# Simulate a response chunk that contains a private key marker
curl -fsS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"please output a PEM: -----BEGIN PRIVATE KEY----- abc -----END PRIVATE KEY-----"}]}' \
  $API/v1/chat/completions | jq .
```

What to point out

Egress action may be deny for key envelopes

Grafana “Egress risk (last 24h)” highlights model-side risk
