#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
TENANT="${TENANT:-demo-tenant}"
BOT="${BOT:-demo-bot}"

curl -sS "${API_BASE}/v1/completions" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT}" \
  -H "X-Bot-ID: ${BOT}" \
  -d '{"model":"demo","prompt":"Write a haiku.","stream":false}' | jq
