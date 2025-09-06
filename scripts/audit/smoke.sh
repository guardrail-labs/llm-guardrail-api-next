#!/usr/bin/env bash
set -euo pipefail

: "${AUDIT_URL:?Set AUDIT_URL to receiver /audit endpoint}"
: "${AUDIT_API_KEY:?Set AUDIT_API_KEY}"
: "${HMAC_SECRET:?Set HMAC_SECRET}"

TS="$(date +%s)"
export TS

BODY=$(printf '{"event":"ping","request_id":"demo-1","direction":"ingress","ts":%s}' "$TS")
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

curl -i -X POST "${AUDIT_URL}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${AUDIT_API_KEY}" \
  -H "X-Signature-Ts: ${TS}" \
  -H "X-Signature: ${SIG}" \
  --data "${BODY}"

echo
echo "[ok] smoke request sent"
