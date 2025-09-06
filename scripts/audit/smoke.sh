#!/usr/bin/env bash
set -euo pipefail

: "${AUDIT_URL:?Set AUDIT_URL to receiver /audit endpoint}"
: "${AUDIT_API_KEY:?Set AUDIT_API_KEY}"
: "${HMAC_SECRET:?Set HMAC_SECRET}"

TS="$(date +%s)"
export TS

# Allow caller to pass a fixed key; else derive from request_id.
IDEMP_KEY="${IDEMP_KEY:-demo-1}"
export IDEMP_KEY

BODY=$(printf '{"event":"ping","request_id":"%s","direction":"ingress","ts":%s}' \
  "${IDEMP_KEY}" "${TS}")
export BODY

# HMAC(secret, ts + "." + body) — must match receiver and forwarder
SIG_HEX="$(python - <<'PY'
import os, hashlib, hmac
secret = os.environ["HMAC_SECRET"].encode()
ts = os.environ["TS"].encode()
body = os.environ["BODY"].encode()
print(hmac.new(secret, ts + b"." + body, hashlib.sha256).hexdigest())
PY
)"
SIG="sha256=${SIG_HEX}"

echo "[info] sending first request (should be accepted)"
curl -sS -i -X POST "${AUDIT_URL}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${AUDIT_API_KEY}" \
  -H "X-Signature-Ts: ${TS}" \
  -H "X-Signature: ${SIG}" \
  -H "X-Idempotency-Key: ${IDEMP_KEY}" \
  --data "${BODY}" | sed -n '1,20p'

echo
echo "[info] sending duplicate request (should be deduped=true)"
curl -sS -i -X POST "${AUDIT_URL}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${AUDIT_API_KEY}" \
  -H "X-Signature-Ts: ${TS}" \
  -H "X-Signature: ${SIG}" \
  -H "X-Idempotency-Key: ${IDEMP_KEY}" \
  --data "${BODY}" | sed -n '1,20p'

echo
echo "[ok] smoke finished"

