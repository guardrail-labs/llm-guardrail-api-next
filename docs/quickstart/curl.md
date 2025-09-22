# Guardrail API quickstart (curl)

Use `curl` for quick smoke-tests and scripting. Replace `YOUR_TOKEN` with a
valid bearer token (or omit the header when running locally without auth).

## Health checks

```bash
export BASE_URL="http://localhost:8000"

curl -sS "$BASE_URL/healthz"
curl -sS "$BASE_URL/readyz"
```

## List decisions

Request the latest decisions (automatically scoped when the API enforces
multitenancy):

```bash
curl -sS \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "$BASE_URL/admin/api/decisions?limit=5"
```

To scope manually, supply the `X-Guardrail-Scope-*` headers:

```bash
curl -sS \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Guardrail-Scope-Tenant: tenant-123" \
  -H "X-Guardrail-Scope-Bot: bot-alpha" \
  "$BASE_URL/admin/api/decisions?limit=5"
```

## List adjudications

```bash
curl -sS \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "$BASE_URL/admin/api/adjudications?limit=5"
```

## Export NDJSON

Exports require a single scope (tenant or bot). The response streams NDJSON which
can be piped to tools such as `jq` or saved to disk.

```bash
curl -sS \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "$BASE_URL/admin/api/export/decisions.ndjson?tenant=tenant-123" \
  -o decisions.ndjson
```
