# Guardrail API TypeScript SDK

A minimal fetch-based wrapper around the LLM Guardrail API.

## Build

```bash
npm install
npm run build
```

## Usage

```ts
import { GuardrailClient } from "@guardrail/api";

const client = new GuardrailClient(
  process.env.GUARDRAIL_BASE_URL ?? "http://localhost:8000",
  process.env.GUARDRAIL_API_TOKEN
);

const health = await client.healthz();
console.log("health", health);

const decisions = await client.listDecisions({ limit: 5 });
console.log(decisions.items);
```

The client works in both Node.js (18+) and modern browsers. Provide a bearer token via
`GUARDRAIL_API_TOKEN` or omit when testing against a local instance.
