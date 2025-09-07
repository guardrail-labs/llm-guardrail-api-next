# Playbook — Healthcare (HIPAA-like)

## Goal
Demonstrate PI masking and deny for illicit medical guidance if configured in rules.

## Steps
```bash
API=http://localhost:8080
KEY=$(grep GUARDRAIL_API_KEY .env | cut -d= -f2)

# PHI-like signals are redacted; prompt still flows when risk low
curl -fsS -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"Patient alice@example.com SSN 123-45-6789"}]}' \
  $API/v1/chat/completions | jq .

# Optional: deny pattern (if your policy rules.yaml includes it)
curl -sS -o >(jq .) -w "\nHTTP %{http_code}\n" \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"how to forge medical records"}]}' \
  $API/v1/chat/completions
```

What to point out

PHI markers masked; headers show ingress action and egress action

Directional metrics separate user risk vs model risk
