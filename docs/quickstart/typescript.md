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

const decisionsDump = await client.exportDecisions({ tenant: "tenant-123" }); // /admin/api/decisions/export?format=jsonl
console.log(decisionsDump.split("\n")[0]);

const adjudicationsDump = await client.exportAdjudications({ bot: "bot-456" }); // /admin/api/adjudications/export.ndjson
console.log(adjudicationsDump.split("\n")[0]);
```

The client uses `fetch`, so it works in browsers out of the box. In Node.js 18+
`fetch` is available globally; earlier versions can bring their own polyfill.
