#!/usr/bin/env bash
set -euo pipefail

: "${FORWARD_URL:?FORWARD_URL is required}"
: "${FORWARD_KEY:?FORWARD_KEY is required}"
: "${HMAC_SECRET:?HMAC_SECRET is required}"

USE_GZIP="${USE_GZIP:-0}"

BODY='{"event":"ping","direction":"ingress","request_id":"smoke-1","ts":'"$(date +%s)"'}'
TS="$(date +%s)"

sign() {
  # args: ts body
  python - "$1" "$2" <<'PY'
import os, sys, hmac, hashlib
ts = sys.argv[1]
body = sys.argv[2]
secret = os.environ["HMAC_SECRET"].encode("utf-8")
msg = (ts + "." + body).encode("utf-8")
print(hmac.new(secret, msg, hashlib.sha256).hexdigest())
PY
}

export HMAC_SECRET
SIG_HEX="$(sign "$TS" "$BODY")"

post_plain() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "$FORWARD_URL" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $FORWARD_KEY" \
    -H "X-Signature-Ts: $TS" \
    -H "X-Signature: sha256=$SIG_HEX" \
    --data "$BODY"
}

post_gzip() {
  code="$(printf '%s' "$BODY" | gzip -c | curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$FORWARD_URL" \
    -H "Content-Type: application/json" \
    -H "Content-Encoding: gzip" \
    -H "X-API-Key: $FORWARD_KEY" \
    -H "X-Signature-Ts: $TS" \
    -H "X-Signature: sha256=$SIG_HEX" \
    --data-binary @-)"
  echo "$code"
}

echo "POST /audit (happy path, USE_GZIP=$USE_GZIP)"
if [ "$USE_GZIP" = "1" ]; then
  code="$(post_gzip)"
else
  code="$(post_plain)"
fi
[ "$code" = "200" ] || { echo "expected 200, got $code"; exit 1; }

echo "Replay same idempotency key"
KEY="smoke-idem-1"
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST "$FORWARD_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $FORWARD_KEY" \
  -H "X-Signature-Ts: $TS" \
  -H "X-Signature: sha256=$SIG_HEX" \
  -H "X-Idempotency-Key: $KEY" \
  --data "$BODY")"
[ "$code" = "200" ] || { echo "expected 200, got $code"; exit 1; }

echo "Stale timestamp should be rejected"
OLD_TS=$((TS - 7200))
OLD_SIG="$(sign "$OLD_TS" "$BODY")"
code="$(curl -s -o /dev/null -w "%{http_code}" -X POST "$FORWARD_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $FORWARD_KEY" \
  -H "X-Signature-Ts: $OLD_TS" \
  -H "X-Signature: sha256=$OLD_SIG" \
  --data "$BODY")"
[ "$code" = "401" ] || { echo "expected 401, got $code"; exit 1; }

echo "OK"
