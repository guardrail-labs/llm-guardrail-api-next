# Guardrail API quickstart (TypeScript)

Build the TypeScript SDK in `clients/typescript` and consume it from Node.js or
browser code.

## Setup

```bash
cd clients/typescript
npm install
npm run build
```

## Example

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(
  process.env.GUARDRAIL_BASE_URL ?? "http://localhost:8000",
  process.env.GUARDRAIL_API_TOKEN
);

const health = await client.healthz();
console.log("health", health);

const decisions = await client.listDecisions({ limit: 5 });
for (const item of decisions.items ?? []) {
  console.log(item.id, item.outcome);
}

const ndjsonDecisions = await client.exportDecisions({ tenant: "tenant-123" });
console.log(ndjsonDecisions.split("\n")[0]); // GET /admin/api/decisions/export?format=jsonl

const ndjsonAdjudications = await client.exportAdjudications({ tenant: "tenant-123" });
console.log(ndjsonAdjudications.split("\n")[0]); // GET /admin/api/adjudications/export.ndjson
```

The client uses `fetch`, so it works in browsers out of the box. In Node.js 18+
`fetch` is available globally; earlier versions can bring their own polyfill.
