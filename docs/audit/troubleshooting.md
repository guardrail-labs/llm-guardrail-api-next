# Troubleshooting

## 401 Unauthorized
- Missing/incorrect `X-API-Key`
- `AUDIT_RECEIVER_REQUIRE_API_KEY=1` but key not set correctly

## 401 Signature required / invalid / stale
- Ensure `AUDIT_RECEIVER_REQUIRE_SIGNATURE=1` and **both** headers present:
  - `X-Signature-Ts` (seconds)
  - `X-Signature` = `sha256=<hex>`
- Compute digest over **exact** raw body: `HMAC(secret, f"{ts}.{raw_body}")`
- Check clock skew vs `AUDIT_RECEIVER_TS_SKEW_SEC`

## 400 Malformed timestamp
- `X-Signature-Ts` must be an integer string

## Idempotency not behaving
- Replays return `200` with `"deduped": true` (not 409/208)
- Ensure `AUDIT_RECEIVER_IDEMP_TTL_SEC` is long enough for your retry policy

## CI smoke fails immediately
- Hitting `/health` on the receiver? Use `/audit` or a container health check
- Inline Python heredocs: read secret from `os.environ` (not a literal string)
- Export `TS` and `BODY` before invoking Python in the smoke script

## Forwarder sending but no events at sink
- Verify `AUDIT_FORWARD_ENABLED=1`, URL points to `/audit`, and secrets match
- Inspect `audit_forwarder_requests_total{result="failure"}`
- Curl the receiver manually with the same headers/body
