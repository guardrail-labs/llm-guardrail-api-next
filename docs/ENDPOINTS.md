# Endpoint Cheatsheet (Core)

## Health & probes
- `GET /livez` → always 200 if process alive
- `GET /readyz` → 200 or 503 based on readiness (bypasses auth/ratelimit)

## Admin (protect with `X-Admin-Key`)
- `GET /admin/api/policy/packs` → list discoverable packs
- `POST /admin/api/policy/validate` {yaml} → lint-only
- `POST /admin/api/policy/reload` → merge + validate + apply (warn|block mode)
- `GET /admin/api/decisions` → filters: `since`, `tenant`, `bot`, `outcome`, `page`, `page_size`
- `GET /admin/api/decisions/export.csv|export.ndjson` → exports

## Public
- `/egress` routes per your integration
- Redaction headers:
  - `X-Redaction-Mode: windowed` (stream transformed)
  - `X-Redaction-Skipped: streaming|oversize` (skip reasons)
