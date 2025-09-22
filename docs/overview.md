# Guardrail API overview

Guardrail API provides policy-driven moderation, safety, and governance controls for LLM traffic. It enables operators to apply consistent rules across inbound prompts, model completions, and downstream automations while preserving auditability and override workflows.

## Core concepts

- **Policies and rulepacks** – Declarative YAML/JSON rules compiled into fast policy engines that evaluate prompts, completions, and structured actions.
- **Decisions** – Policy evaluation results captured with allow/block verdicts, metadata, and override context.
- **Adjudications** – Human or automated follow-up actions that can confirm, override, or annotate a decision.
- **Scopes** – Tenant/bot tuples applied to API tokens that control data visibility and mutability.
- **Queues and DLQ** – Webhook deliveries and async work managed by Redis-backed queues, with a dedicated dead-letter queue for failures.
- **Feature flags** – Runtime toggles that gate preview functionality and operator-facing experiences.

## Feature flags (default → rationale)

- `SCOPE_AUTOCONSTRAIN_ENABLED` **false** → safety-first; enable per env if desired.
- `ADMIN_ENABLE_GOLDEN_ONE_CLICK` **true** (demo) → safe CSRF’d endpoint.
- `METRICS_ROUTE_ENABLED` **true** → standard ops exposure.

## Using the SDKs

- **Python** – Install from `clients/python` (`pip install -e clients/python`) and import `GuardrailClient` from `guardrail_api`. The client exposes health checks, cursor-based decision/adjudication listing, and NDJSON exports.
- **TypeScript** – Build the package in `clients/typescript` (`npm install && npm run build`) and import `GuardrailClient` from `@guardrail/api`. Works with browser `fetch` or Node.js 18+.
- See [`docs/quickstart`](quickstart) for step-by-step examples (curl, Python, and TypeScript) plus the Postman collection in `postman/` for manual exploration.
