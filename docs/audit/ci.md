# CI: Audit Smoke Workflow

We run a containerized receiver and exercise it with signed requests.

- Workflow: `.github/workflows/audit-smoke.yml`
- Steps:
  1. Start receiver (`docker run ... -p 8081:8081`) with **all** required env (including `AUDIT_RECEIVER_SIGNING_SECRET`).
  2. Probe readiness (use `/audit` or container health-check).
  3. Generate `BODY`, `TS`, HMAC over `"{ts}.{BODY}"`.
  4. POST with headers (`X-API-Key`, `X-Signature-Ts`, `X-Signature`, `X-Idempotency-Key`).
  5. Replay with same idempotency key and assert `deduped: true`.

> Make this workflow a **required** check on `main` so we don’t ship broken audit ingest.
