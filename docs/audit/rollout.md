# Audit Forwarding Rollout (staging → prod)

## Env (Forwarder)
- `AUDIT_FORWARD_ENABLED=1`
- `AUDIT_FORWARD_URL=https://<receiver>/audit`
- `AUDIT_FORWARD_API_KEY=<key>`
- `AUDIT_FORWARD_SIGNING_SECRET=<shared-hmac>`
- `AUDIT_FORWARD_RETRIES=3`
- `AUDIT_FORWARD_BACKOFF_MS=100`
- Optional tags: `APP_NAME`, `ENV`

## Env (Receiver)
- `AUDIT_RECEIVER_API_KEY=<key>`
- `AUDIT_RECEIVER_SIGNING_SECRET=<shared-hmac>`
- `AUDIT_RECEIVER_REQUIRE_SIGNATURE=1`
- `AUDIT_RECEIVER_ENFORCE_TS=1`
- `AUDIT_RECEIVER_TS_SKEW_SEC=600`
- `AUDIT_RECEIVER_IDEMP_TTL_SEC=600`
- `AUDIT_RECEIVER_MAX_KEYS=10000`

## Smoke (happy path)
See `scripts/audit/smoke.sh`.

## Negative checks
- Missing `X-Signature-Ts` ⇒ 401 (when ENFORCE_TS=1)
- Stale `X-Signature-Ts` (older than skew) ⇒ 401
- Bad HMAC ⇒ 401
- Duplicate `X-Idempotency-Key` ⇒ `duplicate=true`

## Observability
- `audit_forwarder_requests_total{result="success|failure"}`
- `guardrail_decisions_family_total{family="allow|sanitize|block|verify"}`
- `guardrail_decisions_family_bot_total{tenant="...",bot="...",family="..."}`

## Rollout
Canary 5–10% → 50% → 100%. Keep forwarder logs at INFO.
