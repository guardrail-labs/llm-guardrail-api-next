#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
TENANT="${TENANT:-demo-tenant}"
BOT="${BOT:-demo-bot}"

# sample edit with prompt only (no file required in core)
curl -sS "${API_BASE}/v1/images/edits" \
  -H "X-Tenant-ID: ${TENANT}" \
  -H "X-Bot-ID: ${BOT}" \
  -F 'prompt=make it brighter' \
  -F 'n=1' \
  -F 'size=256x256' | jq
