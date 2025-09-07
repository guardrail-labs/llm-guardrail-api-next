# Receiver (audit sink) configuration

| Variable                         | Required | Default | Purpose |
|---------------------------------|----------|---------|---------|
| `AUDIT_RECEIVER_REQUIRE_API_KEY`| yes      | `0`     | If `1`, reject missing/invalid `X-API-Key`. |
| `AUDIT_RECEIVER_API_KEY`        | yes      | —       | Expected key value. |
| `AUDIT_RECEIVER_REQUIRE_SIGNATURE`| yes    | `0`     | If `1`, verify HMAC signature headers. |
| `AUDIT_RECEIVER_SIGNING_SECRET` | yes      | —       | Shared HMAC secret. |
| `AUDIT_RECEIVER_ENFORCE_TS`     | yes      | `0`     | If `1`, require fresh `X-Signature-Ts`. |
| `AUDIT_RECEIVER_TS_SKEW_SEC`    | no       | `300`   | Allowed clock skew (s). |
| `AUDIT_RECEIVER_IDEMP_TTL_SEC`  | no       | `60`    | Idempotency key TTL (s). |

**Endpoints**
- `POST /audit` – ingest JSON body (application/json).
  - Returns `200` JSON: `{ "ok": true, "deduped": false, ...}`
  - On replay within TTL: `{ "ok": true, "deduped": true, ...}` (still `200`)

**Signature verification**
- Expected: `X-Signature-Ts` + `X-Signature` (`sha256=<hex>`)
- Verify: `hex = HMAC_SHA256(secret, f"{ts}.{raw_body}")`
- If `ENFORCE_TS=1` and `X-Signature-Ts` missing or stale → `401`

**Idempotency**
- If `X-Idempotency-Key` repeats within TTL, receiver flags `deduped: true` and does **not** reprocess.
