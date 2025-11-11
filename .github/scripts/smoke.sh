#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
API_PREFIX="${API_PREFIX:-/v1}"
API_KEY_HEADER="${API_KEY_HEADER:-x-api-key}"
API_KEY_VALUE="${API_KEY_VALUE:-smoke-token}"

echo "::group::Smoke: wait for /healthz"
for i in {1..30}; do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null; then
    echo "healthz OK"
    break
  fi
  echo "waiting... ($i)"
  sleep 2
done
sleep 1
echo "::endgroup::"

echo "::group::Smoke: fetch openapi"
openapi_path="openapi.json"
if ! curl -fsS "${BASE_URL}/${openapi_path}" -o /tmp/openapi.json; then
  echo "default /openapi.json not found, trying prefix ${API_PREFIX}"
  if ! curl -fsS "${BASE_URL}${API_PREFIX}/openapi.json" -o /tmp/openapi.json; then
    echo "ERROR: cannot fetch openapi.json from ${BASE_URL}/{,${API_PREFIX}}/openapi.json"
    echo "Recent logs:"
    docker logs --tail=200 "$(docker ps --format '{{.Names}}' | head -n1)" || true
    exit 1
  else
    openapi_path="${API_PREFIX}/openapi.json"
  fi
fi
echo "OpenAPI fetched from ${BASE_URL}/${openapi_path}"
echo "::endgroup::"

echo "::group::Smoke: discover chat completions path from OpenAPI"
CHAT_PATH="$(python - <<'PY'
import json, sys, re
with open('/tmp/openapi.json','r', encoding='utf-8') as f:
    data=json.load(f)
paths = data.get('paths', {})
cands=[p for p in paths.keys() if re.search(r'/chat/comp(l)?etions$', p)]
if not cands:
    # try common alt paths
    cands=[p for p in paths.keys() if p.endswith('/chat/completions')]
if not cands:
    print("", end="")
    sys.exit(0)
print(sorted(cands, key=len, reverse=True)[0], end="")
PY
)"
if [[ -z "${CHAT_PATH}" ]]; then
  echo "ERROR: could not locate a /chat/completions path in OpenAPI"
  echo "Paths found:"
  python - <<'PY'
import json; d=json.load(open('/tmp/openapi.json')); print("\n".join(d.get('paths',{}).keys()))
PY
  exit 1
fi
echo "Discovered SMOKE_CHAT_PATH=${CHAT_PATH}"
echo "::endgroup::"

echo "::group::Smoke: POST to ${CHAT_PATH} and assert headers"
headers=$(mktemp)
status=$(curl -sS -D "$headers" -o /dev/null -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -H "${API_KEY_HEADER}: ${API_KEY_VALUE}" \
  -X POST \
  --data '{"model":"dummy","messages":[{"role":"user","content":"hello"}]}' \
  "${BASE_URL}${CHAT_PATH}" || true)
echo "HTTP ${status}"
cat "$headers"
grep -qi '^x-guardrail-decision:' "$headers"
grep -qi '^x-guardrail-mode:' "$headers"
test "$status" -ge 200 && test "$status" -lt 300
echo "::endgroup::"

echo "::group::Smoke: 404 still carries X-Guardrail-Mode"
headers404=$(mktemp)
curl -sS -D "$headers404" -o /dev/null "${BASE_URL}/this-definitely-404-$$" || true
cat "$headers404"
grep -qi '^x-guardrail-mode:' "$headers404"
echo "::endgroup::"

echo "Smoke OK"
