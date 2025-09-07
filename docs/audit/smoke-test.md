# Smoke Testing

## One-liner curl
```bash
export FORWARD_URL="http://localhost:8081/audit"
export FORWARD_KEY="test-key"
export HMAC_SECRET="test-secret"
export TS="$(date +%s)"
export BODY='{"event":"ping","request_id":"demo-1","direction":"ingress","ts":'"$TS"'}'
export SIG="sha256=$(python - <<'PY'
import os, hmac, hashlib
ts=os.environ["TS"].encode()
body=os.environ["BODY"].encode()
sec=os.environ["HMAC_SECRET"].encode()
print(hmac.new(sec, ts+b"."+body, hashlib.sha256).hexdigest())
PY
)"

curl -i -X POST "$FORWARD_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $FORWARD_KEY" \
  -H "X-Signature-Ts: $TS" \
  -H "X-Signature: $SIG" \
  -H "X-Idempotency-Key: demo-key-1" \
  --data "$BODY"
```

### Scripted
`bash scripts/audit/smoke.sh`   # uses FORWARD_URL, FORWARD_KEY, HMAC_SECRET

### Expected

First POST → 200, body includes "deduped": false

Replay with same idempotency key → 200, "deduped": true
