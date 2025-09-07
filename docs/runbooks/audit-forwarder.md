# Audit Forwarder / Receiver Runbook

## What this is
Forwarder: your app emits JSON audit events and signs them (HMAC) before POSTing.
Receiver: validates API key + signature + timestamp freshness + idempotency, persists.

## Turn it on
**App (forwarder)** – set env:
- `AUDIT_FORWARD_ENABLED=1`
- `AUDIT_FORWARD_URL=https://audit-sink.example.com/audit`
- `AUDIT_FORWARD_API_KEY=<api-key>`
- `AUDIT_FORWARD_SIGNING_SECRET=<hmac-secret>`

**Receiver** – set env:
- `AUDIT_RECEIVER_REQUIRE_API_KEY=1`
- `AUDIT_RECEIVER_API_KEY=<api-key>`
- `AUDIT_RECEIVER_REQUIRE_SIGNATURE=1`
- `AUDIT_RECEIVER_SIGNING_SECRET=<hmac-secret>`
- `AUDIT_RECEIVER_ENFORCE_TS=1`
- `AUDIT_RECEIVER_TS_SKEW_SEC=300`
- `AUDIT_RECEIVER_IDEMP_TTL_SEC=60`

## Prod smoke (one-liner)
```bash
FORWARD_URL=https://audit-sink.example.com/audit \
FORWARD_KEY=... \
HMAC_SECRET=... \
bash scripts/audit/prod_smoke.sh
```

## Alerts

Import `monitoring/prometheus/alerts/audit_forwarder.yml`.

- **AnyFailure (warn):** any non-2xx from forwarder in 5m
- **FailureRateHigh (crit):** >2% failures for 10m

## Secret rotation (no downtime)

1. Add new secret to receiver and allow both old+new for 10–15 minutes.
2. Switch forwarder to new secret.
3. Remove old secret from receiver.

## Common errors

- **401 invalid signature**
  
  Secrets mismatch or body modified after signing. Ensure forwarder signs exact JSON.
- **401 stale timestamp**
  
  Clock drift or `X-Signature-Ts` older than `AUDIT_RECEIVER_TS_SKEW_SEC`.
- **200 but "deduped": true**
  
  Same `X-Idempotency-Key` reused (ok for retries). Use a new key per logical event.

## Observability

- Forwarder counter: `audit_forwarder_requests_total{result="success|failure"}`
- Receiver should log: decision, request_id, deduped, reason.

## Runbook quick actions

- Spike in failures → check receiver health, DNS, TLS, WAF; verify API key & secret.
- Repeated stale ts → check NTP/clock skew on forwarder nodes.
- High dedupe rate → inspect client idempotency key reuse.
