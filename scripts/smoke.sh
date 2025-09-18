#!/usr/bin/env bash
set -euo pipefail

ADMIN_KEY="${ADMIN_KEY:-dev-admin-key}"
BASE="${BASE:-http://localhost:8080}"

echo "== health =="
curl -fsS "$BASE/readyz" >/dev/null
curl -fsS "$BASE/livez"  >/dev/null
echo "ok"

echo "== list packs =="
curl -fsS -H "X-Admin-Key: $ADMIN_KEY" "$BASE/admin/api/policy/packs" | jq '.packs|length'

echo "== bind demo packs =="
curl -fsS -X PUT -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  "$BASE/admin/bindings" -d '{
  "bindings": [
    {"tenant":"demo","bot":"site","rules_path":"pii_redact"},
    {"tenant":"demo","bot":"site","rules_path":"secrets_redact"}
  ]
}' >/dev/null
echo "ok"

echo "== reload =="
curl -fsS -X POST -H "X-Admin-Key: $ADMIN_KEY" "$BASE/admin/api/policy/reload" | jq -e '.status=="ok"' >/dev/null
echo "ok"

echo "== egress demo =="
OUT="$(curl -fsS -H 'X-Tenant-Id: demo' -H 'X-Bot-Id: site' \
  "$BASE/echo" -d 'Email a.b+z@example.co.uk JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy')"
echo "$OUT" | grep -qi "example.co.uk" && { echo "expected redaction, saw plaintext"; exit 1; }
echo "ok"

echo "== decisions sample =="
curl -fsS -H "X-Admin-Key: $ADMIN_KEY" "$BASE/admin/api/decisions?since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | jq '.items|length'

echo "smoke OK"
