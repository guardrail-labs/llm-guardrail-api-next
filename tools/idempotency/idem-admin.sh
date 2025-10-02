#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
idem-admin.sh recent|get <key>|purge <key>

Env:
  IDEM_BASE_URL  Base URL, e.g. https://api.stage.example.com
  IDEM_TOKEN     Bearer token with admin scope
  IDEM_TENANT    Optional tenant header (X-Tenant)

Examples:
  IDEM_BASE_URL=... IDEM_TOKEN=... ./idem-admin.sh recent
  ./idem-admin.sh get abc123
  ./idem-admin.sh purge abc123
USAGE
}

need_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing env: $name" >&2
    exit 2
  fi
}

curl_base() {
  local path="$1"
  local method="${2:-GET}"
  need_env IDEM_BASE_URL
  need_env IDEM_TOKEN
  local args=(-fsSL -X "$method" "${IDEM_BASE_URL}${path}"
              -H "Authorization: Bearer ${IDEM_TOKEN}")
  if [[ -n "${IDEM_TENANT:-}" ]]; then
    args+=(-H "X-Tenant: ${IDEM_TENANT}")
  fi
  curl "${args[@]}"
}

cmd_recent() { curl_base "/admin/idempotency/recent"; }
cmd_get()    { curl_base "/admin/idempotency/$1"; }
cmd_purge()  { curl_base "/admin/idempotency/$1" "DELETE"; }

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  case "$1" in
    recent) shift; cmd_recent "$@";;
    get)    shift; [[ $# -eq 1 ]] || { usage; exit 2; }; cmd_get "$1";;
    purge)  shift; [[ $# -eq 1 ]] || { usage; exit 2; }; cmd_purge "$1";;
    -h|--help) usage;;
    *) usage; exit 2;;
  esac
}
main "$@"
