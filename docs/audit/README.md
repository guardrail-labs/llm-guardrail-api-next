# Audit Forwarding & Receiver (Secure, Idempotent)

This package wires your app (the **forwarder**) to an audit sink (the **receiver**) with:

- **Auth**: `X-API-Key`
- **Integrity + anti-replay**: HMAC-SHA256 signature over `"{ts}.{raw_body}"`, headers `X-Signature` and `X-Signature-Ts`
- **Idempotency**: `X-Idempotency-Key` to safely retry without double-processing
- **Metrics**: Prometheus counters on both sides

```text
+------------+            HTTPS            +-------------+
|  App / API | -- signed JSON + headers --> |  Receiver  |
| (forwarder)|                           |  (audit sink) |
+------------+                           +-------------+
      |                                         |
  emit_audit_event(...)                     store/stream
      |                                         |
prom counters                                prom counters
```

TL;DR: Turn it on (prod/stage)

Forwarder (your app) env

AUDIT_FORWARD_ENABLED=1
AUDIT_FORWARD_URL=https://audit.example.com/audit
AUDIT_FORWARD_API_KEY=YOUR_SHARED_KEY
AUDIT_FORWARD_SIGNING_SECRET=YOUR_SHARED_HMAC_SECRET
AUDIT_FORWARD_RETRIES=3
AUDIT_FORWARD_BACKOFF_MS=100


Receiver (audit sink) env

AUDIT_RECEIVER_REQUIRE_API_KEY=1
AUDIT_RECEIVER_API_KEY=YOUR_SHARED_KEY
AUDIT_RECEIVER_REQUIRE_SIGNATURE=1
AUDIT_RECEIVER_SIGNING_SECRET=YOUR_SHARED_HMAC_SECRET
AUDIT_RECEIVER_ENFORCE_TS=1
AUDIT_RECEIVER_TS_SKEW_SEC=300
AUDIT_RECEIVER_IDEMP_TTL_SEC=60


Smoke test

# minimal happy-path payload
BODY='{"event":"ping","request_id":"demo-1","direction":"ingress","ts":'$(date +%s)'}'
TS="$(date +%s)"
SIG="sha256=$(python - <<'PY'
import os,sys,hmac,hashlib
secret=os.environ["HMAC_SECRET"].encode()
ts=os.environ["TS"].encode()
body=os.environ["BODY"].encode()
print(hmac.new(secret, ts+b"."+body, hashlib.sha256).hexdigest())
PY
)"
curl -i -X POST "$FORWARD_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $FORWARD_KEY" \
  -H "X-Signature-Ts: $TS" \
  -H "X-Signature: $SIG" \
  -H "X-Idempotency-Key: demo-key-1" \
  --data "$BODY"


If you get 200 plus a JSON body (and deduped: false the first time), you’re live.

Headers & Signing

X-API-Key: shared static key (simple client allow-list)

X-Signature-Ts: POSIX seconds (string)

X-Signature: sha256=<hex> where

digest = HMAC_SHA256( secret, f"{ts}.{raw_body}" )


Important: sign the exact raw JSON bytes you send.

X-Idempotency-Key: optional, recommended for clients; the receiver dedupes
within the TTL window and returns a 200 with "deduped": true on replay.

What the forwarder adds automatically

The internal facade app/services/audit.emit_audit_event normalizes your events to include:

policy_version (if missing)

request_id (UUID if missing)

ts (unix seconds if missing)

service and (when present) env

You can safely pass a minimal dict and it will be annotated.

Operational Notes

Replay protection: set AUDIT_RECEIVER_ENFORCE_TS=1; missing/old X-Signature-Ts yields 401.

Retries: forwarder retries non-2xx with linear backoff; failures bump audit_forwarder_requests_total{result="failure"}.

Rollbacks: set AUDIT_FORWARD_ENABLED=0 on the app or temporarily relax signature/timestamp checks on the receiver.

See also:

forwarder-config.md

receiver-config.md

smoke-test.md

ci.md

metrics.md

troubleshooting.md
