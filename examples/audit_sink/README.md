# Audit Receiver Example

A tiny FastAPI service that accepts audit events from your forwarder, verifies
HMAC signatures, enforces (optional) API key, and de-dupes requests via
`X-Idempotency-Key`.

## Run

```bash
python -m pip install fastapi uvicorn
AUDIT_RECEIVER_API_KEY=dev-key \
AUDIT_RECEIVER_SIGNING_SECRET=supersecret \
uvicorn examples.audit_sink.app:app --reload --port 8081
```

Health:

```bash
curl localhost:8081/health
```

Point your forwarder at it

In your guardrail API environment:

```bash
export AUDIT_FORWARD_ENABLED=1
export AUDIT_FORWARD_URL=http://localhost:8081/audit
export AUDIT_FORWARD_API_KEY=dev-key
export AUDIT_FORWARD_SIGNING_SECRET=supersecret
```

Exercise any endpoint that emits an audit event. The receiver logs accepted
events, and duplicates return "duplicate": true.

### Optional knobs

- `AUDIT_RECEIVER_REQUIRE_SIGNATURE=1` — reject if signature missing
- `AUDIT_RECEIVER_ENFORCE_TS=1` & `AUDIT_RECEIVER_TS_SKEW_SEC=600` — freshness check
- `AUDIT_RECEIVER_IDEMP_TTL_SEC=600` — duplicate window (seconds)
- `AUDIT_RECEIVER_MAX_KEYS=10000` — max in-memory idempotency keys
