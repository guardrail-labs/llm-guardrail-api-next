#!/usr/bin/env bash
# Simple production smoke for audit receiver.
# Requires: curl, Python 3
#
# Required env:
#   FORWARD_URL   e.g. https://audit-sink.example.com/audit
#   FORWARD_KEY   API key value for X-API-Key
#   HMAC_SECRET   shared secret for HMAC signing
#
# Optional:
#   IDEMP_KEY     idempotency key (default: "smoke-$(date +%s)")
#   BODY          JSON payload (default: minimal valid event)

set -euo pipefail

: "${FORWARD_URL:?set FORWARD_URL}"
: "${FORWARD_KEY:?set FORWARD_KEY}"
: "${HMAC_SECRET:?set HMAC_SECRET}"

IDEMP_KEY="${IDEMP_KEY:-smoke-$(date +%s)}"
BODY="${BODY:-"{\"event\":\"smoke\",\"direction\":\"ingress\",\"request_id\":\"$IDEMP_KEY\"}"}"

sign() {
  # args: ts, body -> prints hex digest of HMAC-SHA256(ts + "." + body)
  TS="$1" BODY_STR="$2" HMAC_SECRET="$HMAC_SECRET" \
  python - <<'PY'
import os, hmac, hashlib, sys
ts=os.environ['TS']; body=os.environ['BODY_STR']
key=os.environ['HMAC_SECRET'].encode('utf-8')
msg=(ts + "." + body).encode('utf-8')
print(hmac.new(key, msg, hashlib.sha256).hexdigest())
PY
}

post() {
  local ts="$1" sig="$2" out="$3"
  curl -sS -o "$out" -w "%{http_code}" -X POST "$FORWARD_URL" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $FORWARD_KEY" \
    -H "X-Signature-Ts: $ts" \
    -H "X-Signature: sha256=$sig" \
    -H "X-Idempotency-Key: $IDEMP_KEY" \
    --data "$BODY"
}

tmp1="$(mktemp)"; trap 'rm -f "$tmp1" "$tmp2" "$tmp3"' EXIT
TS="$(date +%s)"
SIG="$(sign "$TS" "$BODY")"

echo "== 1) happy path"
code="$(post "$TS" "$SIG" "$tmp1")"
echo "HTTP $code"
if [ "$code" != "200" ]; then
  echo "FAIL: expected 200"; cat "$tmp1"; exit 1
fi
if grep -q '"deduped"[[:space:]]*:[[:space:]]*true' "$tmp1"; then
  echo "FAIL: first request should not be deduped"; exit 1
fi
echo "OK"

echo "== 2) replay with same idempotency key (should dedupe)"
tmp2="$(mktemp)"
code="$(post "$TS" "$SIG" "$tmp2")"
echo "HTTP $code"
if [ "$code" != "200" ]; then
  echo "FAIL: expected 200 on replay"; cat "$tmp2"; exit 1
fi
if ! grep -q '"deduped"[[:space:]]*:[[:space:]]*true' "$tmp2"; then
  echo "FAIL: expected deduped=true on replay"; cat "$tmp2"; exit 1
fi
echo "OK"

echo "== 3) stale timestamp should be rejected"
tmp3="$(mktemp)"
STALE_TS="$((TS - 100000))"
STALE_SIG="$(sign "$STALE_TS" "$BODY")"
code="$(post "$STALE_TS" "$STALE_SIG" "$tmp3" || true)"
echo "HTTP $code"
if [ "$code" = "200" ]; then
  echo "FAIL: expected 401/400 for stale timestamp"; cat "$tmp3"; exit 1
fi
echo "OK"

echo "✅ smoke passed"
