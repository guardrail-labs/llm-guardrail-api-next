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

echo "== reload (CSRF) =="
CSRF="$(openssl rand -hex 16 2>/dev/null || uuidgen 2>/dev/null || date +%s)"
curl -fsS -X POST \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -H "Cookie: csrf=$CSRF" \
  -H "X-CSRF-Token: $CSRF" \
  -d "{\"csrf_token\":\"$CSRF\"}" \
  "$BASE/admin/api/policy/reload" | jq -e '.status=="ok"' >/dev/null
echo "ok"

echo "== egress redaction demo via /admin/echo =="
DEMO='Email a.b+z@example.co.uk JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy'
OUT="$(curl -fsS -G \
  -H "X-Admin-Key: $ADMIN_KEY" \
  --data-urlencode "text=$DEMO" \
  "$BASE/admin/echo")"
echo "$OUT" | grep -qi "example.co.uk" && { echo "expected redaction, saw plaintext"; exit 1; }
echo "ok"

echo "== decisions sample =="
curl -fsS -H "X-Admin-Key: $ADMIN_KEY" "$BASE/admin/api/decisions?since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | jq '.items|length'

echo "== /version =="
curl -fsS "$BASE/version" | jq .

echo "smoke OK"
