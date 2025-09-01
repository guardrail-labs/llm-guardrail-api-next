# LLM Guardrail API (Core -next)

A modular Guardrail API that intercepts prompts/responses to LLMs, sanitizes or blocks harmful input/output, verifies unclear intent, wires enterprise telemetry (audit, multitenancy, quotas), and supports OpenAI/Azure-compatible endpoints.

## Quick Start

```bash
# 1) Create & populate env (see .env.example)
cp .env.example .env

# 2) Install
pip install -r requirements.txt

# 3) Run (dev)
uvicorn app.main:app --reload --port 8000

# 4) Verify health
curl -s http://localhost:8000/v1/health | jq
```

OpenAI-Compatible Endpoints

GET /v1/health (simple health + policy version)

GET /v1/models

POST /v1/chat/completions (stream & non-stream)

POST /v1/completions (stream & non-stream)

POST /v1/moderations

POST /v1/embeddings

POST /v1/images/generations

POST /v1/images/edits

POST /v1/images/variations

Azure-Compatible Endpoints

POST /openai/deployments/{deployment_id}/chat/completions

POST /openai/deployments/{deployment_id}/embeddings

See docs/OPENAI_AZURE_COMPAT.md for payload details and headers.

Guardrail Behavior

All ingress/egress is processed by:

Ingress: sanitize, dynamic redactions (threat feed), detectors (deny/allow/clarify), audit emit, metrics.

Egress: streaming and non-streaming checks with redactions/deny and audit emit.

Quotas: per-tenant/bot hard or soft caps (minute/day) with 429 hard enforcement and Prometheus counter.

See docs/QUOTAS.md for configuration and expected behavior.

Metrics & Audit

Prometheus counters for decision families, per-tenant/bot breakdown, verifier outcomes, and quota rejects.

Audit events include tenant_id, bot_id, request_id, policy version, bytes, hashes, and meta.client.

Examples

Use the runnable scripts in examples/curl/:

chat.sh, completions.sh, embeddings.sh, moderations.sh

images_generations.sh, images_edits.sh, images_variations.sh

Set API_BASE and headers in each script (see comments) or export from environment.

Environment

See .env.example for all keys and defaults.

Testing
ruff check --fix .
mypy .
pytest -q


All tests must be green before merge.
