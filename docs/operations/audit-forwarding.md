# Audit Forwarding – Operator Runbook

This service emits guardrail audit events to a receiver with optional HMAC signing and idempotency.

## Env Vars (Emitter)

```bash
AUDIT_FORWARD_ENABLED=1
AUDIT_FORWARD_URL=https://<receiver>/ingest
AUDIT_FORWARD_API_KEY=<emit-api-key>
AUDIT_FORWARD_SIGNING_SECRET=<hmac-secret>   # enables signature headers
```

The forwarder signs the request body with HMAC-SHA256 using header:

```
X-Signature-Ts: Unix seconds

X-Signature: sha256=<hexdigest>, where the message is "{ts}.{raw_json_body}"
```

Env Vars (Receiver)
```
AUDIT_RECEIVER_REQUIRE_API_KEY=1
AUDIT_RECEIVER_API_KEY=<same-as-emitter>
AUDIT_RECEIVER_REQUIRE_SIGNATURE=1
AUDIT_RECEIVER_ENFORCE_TS=1
AUDIT_RECEIVER_TS_SKEW_SEC=300
AUDIT_RECEIVER_IDEMP_TTL_SEC=3600
PORT=8081
```

If ENFORCE_TS=1, the receiver requires X-Signature-Ts and rejects stale timestamps.

Idempotency keys are recorded after the payload is validated and accepted.

## Smoke Test (local)
```bash
# In one terminal
docker build -t audit-receiver examples/audit_sink
docker run -it --rm -p 8081:8081 \
  -e AUDIT_RECEIVER_REQUIRE_API_KEY=1 \
  -e AUDIT_RECEIVER_API_KEY=test-key \
  -e AUDIT_RECEIVER_REQUIRE_SIGNATURE=1 \
  -e AUDIT_RECEIVER_ENFORCE_TS=1 \
  -e AUDIT_RECEIVER_TS_SKEW_SEC=300 \
  -e AUDIT_RECEIVER_IDEMP_TTL_SEC=60 \
  --name sink audit-receiver

# In another terminal (signed request)
export URL=http://localhost:8081/ingest
export KEY=test-key
export HMAC_SECRET=test-secret
export BODY='{"event":"ping","request_id":"local-1","direction":"ingress","ts":'$(date +%s)'}'
export TS="$(date +%s)"
SIG=$(python - <<'PY'
import os,hmac,hashlib
print(hmac.new(os.environ["HMAC_SECRET"].encode(),
               (os.environ["TS"]+"."+os.environ["BODY"]).encode(),
               hashlib.sha256).hexdigest())
PY
)
curl -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -H "X-Signature-Ts: $TS" \
  -H "X-Signature: sha256=$SIG" \
  -H "X-Idempotency-Key: local-key-1" \
  --data "$BODY"
```

## Secret Rotation

1. Add new API key & HMAC secret on the receiver (temporarily allow both).
2. Update emitter env to the new pair; deploy and verify CI smoke passes.
3. Remove the old key/secret from the receiver.
4. Record the rotation in your ops log.

## Prometheus Alerts

Use prometheus/alerts.yml. Key alerts:

- AuditForwarderFailures — forwarder cannot deliver events.
- NoGuardrailDecisions — suspiciously quiet pipeline.
- HighSanitizeRate — bursts of redactions, investigate.

## Troubleshooting

- **401 Missing/Bad signature:** Check AUDIT_FORWARD_SIGNING_SECRET and that X-Signature is
  sha256=... over "{ts}.{body}".
- **401 Stale timestamp:** Clock skew or wrong AUDIT_RECEIVER_TS_SKEW_SEC.
- **409/208 duplicate:** Reuse of X-Idempotency-Key. Use a fresh key per unique event.
- **No audits appearing:** Verify emitter env, URL, and check receiver /health.
