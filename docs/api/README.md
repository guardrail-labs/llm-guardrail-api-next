# Admin API Reference

The Admin API exposes operational surfaces for tenants, bots, and policy adjudication data. All endpoints require an authenticated admin identity and enforce bearer tokens issued by your control plane.

## Overview

### Authentication options
- **OIDC sessions** – Browser operators authenticate via your IdP. Session cookies must be exchanged for a CSRF token before calling any mutating endpoint.
- **Legacy admin tokens** – Static bearer tokens still work for GET endpoints and are convenient for automation. Rotate them periodically.
- **Service tokens** – Recommended for batch jobs. Create scoped service tokens and pass them with the `Authorization: Bearer <token>` header.

> **CSRF**: Mutations issued from browsers (POST/PATCH/DELETE) must include the `X-CSRF-Token` header. The examples below use only `GET` routes, but the CSRF requirement still applies for override workflows.

### Common query parameters

| Parameter | Description |
|-----------|-------------|
| `tenant`  | Filter by tenant. Accepts a single tenant id or a repeated query string when explicitly requesting multiple tenants. |
| `bot`     | Filter by bot id within the tenant filter. |
| `limit`   | Page size (1–500). Default is 50. |
| `cursor`  | Opaque cursor returned by a previous page. Required when paginating backwards. |
| `dir`     | Cursor direction. Use `fwd` (default) to fetch the next page or `back` to read the previous page. |

When executing idempotent mutating requests, you can optionally include `Idempotency-Key: <uuid>` to guarantee at-most-once semantics. The server already honors this header for override workflows.

### Effective scope headers

Every Admin API response echoes the resolved scopes to make multi-tenant behavior explicit:

- `X-Effective-Tenant: <tenant>` for a single tenant, `tenant1,tenant2` when multiple tenants are active, or `*` when unrestricted.
- `X-Effective-Bot: <bot>` for a single bot, `bot1,bot2` for multiple bots, or `*` for wildcard access.

Tokens that are scoped to multiple tenants or bots are automatically constrained to a single scope unless the request specifies explicit filters. Always pass `tenant`/`bot` query parameters when using multi-scope tokens to avoid unexpected `*` responses.

## Health and metadata endpoints

### `GET /healthz`

Basic process health used for liveness checks.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/healthz"
```

Sample response:

```json
{
  "status": "ok",
  "uptime_seconds": 53211,
  "redis": "ok"
}
```

### `GET /readyz`

Detailed readiness probe. The endpoint returns `503` if any configured Redis consumer is degraded.

```bash
curl -i -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/readyz"
```

Sample response:

```http
HTTP/1.1 200 OK
X-Effective-Tenant: *
X-Effective-Bot: *
Content-Type: application/json

{
  "status": "ok",
  "redis": {
    "primary": "ok"
  },
  "consumers": {
    "decision-stream": "ok"
  }
}
```

> When a consumer is down, the response changes to `HTTP/1.1 503 Service Unavailable` with the failing component listed under `consumers`.

### `GET /version`

Returns build metadata (OCI labels) and feature flags for audits.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/version"
```

Sample response:

```json
{
  "version": "2024.06.0",
  "commit": "abc1234",
  "build_date": "2024-06-05T17:42:03Z",
  "features": {
    "cursor_exports": true
  }
}
```

Python SDK:

```python
from guardrail_api import GuardrailClient
import httpx

client = GuardrailClient(base_url=GUARDRAIL_BASE_URL, token=ADMIN_TOKEN)
health = client.healthz()
ready = client.readyz()
version = httpx.get(
    f"{GUARDRAIL_BASE_URL}/version",
    headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    timeout=10.0,
).json()
```

TypeScript SDK:

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(process.env.GUARDRAIL_BASE_URL!, process.env.ADMIN_TOKEN);
const health = await client.healthz();
const ready = await client.readyz();
const versionResponse = await fetch(`${process.env.GUARDRAIL_BASE_URL}/version`, {
  headers: { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` }
});
const version = await versionResponse.json();
```

## Decisions API

### `GET /admin/api/decisions`

Cursor-ordered list of decisions sorted by `(ts, index)` to keep ordering stable as new events arrive.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/decisions?tenant=tenant-a&bot=bot-1&limit=2"
```

Sample response:

```json
{
  "items": [
    {
      "id": "dec_001",
      "ts": "2024-06-05T12:00:00Z",
      "tenant": "tenant-a",
      "bot": "bot-1",
      "outcome": "allow"
    },
    {
      "id": "dec_000",
      "ts": "2024-06-05T11:59:55Z",
      "tenant": "tenant-a",
      "bot": "bot-1",
      "outcome": "block"
    }
  ],
  "limit": 2,
  "dir": "fwd",
  "next_cursor": "eyJ0cyI6ICIyMDI0LTA2LTA1VDEyOjAwOjAwWiIsICJpbmRleCI6IDEyfQ==",
  "prev_cursor": null
}
```

To fetch the next page, pass `cursor=<next_cursor>` and keep `dir=fwd` (default):

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/decisions?tenant=tenant-a&cursor=eyJ0cyI6ICIyMDI0LTA2LTA1VDEyOjAwOjAwWiIsICJpbmRleCI6IDEyfQ=="
```

To page backwards, switch to `dir=back` and provide the previous cursor:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/decisions?tenant=tenant-a&dir=back&cursor=eyJ0cyI6ICIyMDI0LTA2LTA1VDEyOjAwOjAwWiIsICJpbmRleCI6IDEyfQ=="
```

Python SDK:

```python
from guardrail_api import GuardrailClient

client = GuardrailClient(base_url=GUARDRAIL_BASE_URL, token=ADMIN_TOKEN)
page = client.list_decisions(tenant="tenant-a", bot="bot-1", limit=100)
if page.get("next_cursor"):
    next_page = client.list_decisions(
        tenant="tenant-a",
        bot="bot-1",
        cursor=page["next_cursor"],
    )
```

TypeScript SDK:

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(process.env.GUARDRAIL_BASE_URL!, process.env.ADMIN_TOKEN);
const page = await client.listDecisions({ tenant: "tenant-a", bot: "bot-1", limit: 100 });
if (page.next_cursor) {
  const nextPage = await client.listDecisions({
    tenant: "tenant-a",
    bot: "bot-1",
    cursor: page.next_cursor,
    dir: "fwd"
  });
}
```

### Export decisions — `GET /admin/api/decisions/export?format=jsonl`

Streams the decision list in newline-delimited JSON (JSONL). Use explicit tenant/bot filters with multi-scope credentials.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/decisions/export?format=jsonl&tenant=tenant-a&bot=bot-1" \
  -o decisions.jsonl
```

Python SDK:

```python
from guardrail_api import GuardrailClient

client = GuardrailClient(base_url=GUARDRAIL_BASE_URL, token=ADMIN_TOKEN)
ndjson = client.export_decisions(tenant="tenant-a", bot="bot-1")
with open("decisions.jsonl", "w", encoding="utf-8") as fh:
    fh.write(ndjson)
```

TypeScript SDK:

```ts
import { GuardrailClient } from "@guardrail/api";
import { promises as fs } from "fs";

const client = new GuardrailClient(process.env.GUARDRAIL_BASE_URL!, process.env.ADMIN_TOKEN);
const ndjson = await client.exportDecisions({ tenant: "tenant-a", bot: "bot-1" });
await fs.writeFile("decisions.jsonl", ndjson, "utf8");
```

## Adjudications API

### `GET /admin/api/adjudications`

Supports the same cursor semantics as the decisions endpoint.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/adjudications?tenant=tenant-a&bot=bot-1&limit=1"
```

Sample response:

```json
{
  "items": [
    {
      "id": "adj_010",
      "ts": "2024-06-05T12:05:00Z",
      "tenant": "tenant-a",
      "bot": "bot-1",
      "outcome": "allow",
      "rule_id": "rule-override"
    }
  ],
  "limit": 1,
  "dir": "fwd",
  "next_cursor": null,
  "prev_cursor": "eyJ0cyI6ICIyMDI0LTA2LTA1VDEyOjA0OjU5WiIsICJpbmRleCI6IDB9"
}
```

Python SDK:

```python
from guardrail_api import GuardrailClient

client = GuardrailClient(base_url=GUARDRAIL_BASE_URL, token=ADMIN_TOKEN)
page = client.list_adjudications(tenant="tenant-a", bot="bot-1", limit=50)
if page.get("prev_cursor"):
    previous_page = client.list_adjudications(
        tenant="tenant-a",
        bot="bot-1",
        cursor=page["prev_cursor"],
        dir="back",
    )
```

TypeScript SDK:

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(process.env.GUARDRAIL_BASE_URL!, process.env.ADMIN_TOKEN);
const page = await client.listAdjudications({ tenant: "tenant-a", bot: "bot-1", limit: 50 });
if (page.prev_cursor) {
  const prevPage = await client.listAdjudications({
    tenant: "tenant-a",
    bot: "bot-1",
    cursor: page.prev_cursor,
    dir: "back"
  });
}
```

### Export adjudications — `GET /admin/api/adjudications/export.ndjson`

Returns an NDJSON stream with the adjudication history.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GUARDRAIL_BASE_URL/admin/api/adjudications/export.ndjson?tenant=tenant-a"
```

Python SDK:

```python
from guardrail_api import GuardrailClient

client = GuardrailClient(base_url=GUARDRAIL_BASE_URL, token=ADMIN_TOKEN)
ndjson = client.export_adjudications(tenant="tenant-a", bot="bot-1")
print(ndjson.splitlines()[0])
```

TypeScript SDK:

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(process.env.GUARDRAIL_BASE_URL!, process.env.ADMIN_TOKEN);
const ndjson = await client.exportAdjudications({ tenant: "tenant-a", bot: "bot-1" });
console.log(ndjson.split("\n")[0]);
```

---

Use the effective scope headers and explicit query filters to guarantee you are working within the intended tenant/bot boundaries when operating in multi-tenant environments.

### Scope (read-only)
- `GET /admin/api/scope/effective` → JSON mirror of `X-Guardrail-Scope-*` effective scope headers.
- `GET /admin/api/scope/bindings?tenant=...&bot=...` → policy packs + mitigation overrides.
- `GET /admin/api/scope/secrets?tenant=...&bot=...` → **secret set names only** (no values).

All endpoints enforce admin RBAC and scope autoconstrain; multi-scope tokens must provide explicit `tenant` and `bot`.
