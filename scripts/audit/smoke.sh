#!/usr/bin/env bash
set -euo pipefail

: "${AUDIT_URL:?Set AUDIT_URL to receiver /audit endpoint}"
: "${AUDIT_API_KEY:?Set AUDIT_API_KEY}"
: "${HMAC_SECRET:?Set HMAC_SECRET}"

# Single timestamp used for both body and header to avoid skew
TS="$(date +%s)"
export TS

# Build body with the same TS
BODY=$(printf '{"event":"ping","request_id":"demo-1","direction":"ingress","ts":%s}' "$TS")
export BODY

# Compute HMAC over the raw JSON body (matches forwarder default)
# If your receiver signs ts + "." + body instead, change the Python line accordingly.
SIG_HEX="$(python - <<'PY'
import os, hashlib, hmac
secret = os.environ["HMAC_SECRET"].encode()
body = os.environ["BODY"].encode()
print(hmac.new(secret, body, hashlib.sha256).hexdigest())
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
