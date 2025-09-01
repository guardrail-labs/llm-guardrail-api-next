#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
TENANT="${TENANT:-demo-tenant}"
BOT="${BOT:-demo-bot}"

# variants without real file (placeholder path)
# Replace /tmp/one.png with a real local file if desired
: "${IMG:=/tmp/one.png}"

if [ ! -f "${IMG}" ]; then
  echo "Creating a 1x1 PNG placeholder at ${IMG}"
  printf '\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\1\0\0\0\1\x08\x02\0\0\0\x90wS\xde\0\0\0\nIDATx\x9cc`\0\0\0\x02\0\x01\xe2!\xbc3\0\0\0\0IEND\xaeB`\x82' > "${IMG}"
fi

curl -sS "${API_BASE}/v1/images/variations" \
  -H "X-Tenant-ID: ${TENANT}" \
  -H "X-Bot-ID: ${BOT}" \
  -F "image=@${IMG}" \
  -F 'n=1' \
  -F 'size=256x256' | jq
