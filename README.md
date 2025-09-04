# LLM Guardrail API

Intercept • Enforce • Redact • Verify — for any LLM

[![CI](https://img.shields.io/badge/tests-green-success)]() [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)]()

A production-ready, LLM-agnostic security layer for prompts and responses.

- **Policy enforcement** for PII, secrets, illicit content, and jailbreaks
- **Multimodal redactions** (text, files, images, audio, PDFs)
- **OpenAI-compatible** proxy routes (or import as a library)
- **Transparent provenance** via `debug.sources` and redaction spans
- **Verifier** path for gray-areas (block/clarify/allow)

For a show-ready demo with architecture diagram, curl scripts, and a mini React dashboard, see [docs/DEMO_KIT.md](docs/DEMO_KIT.md).

## Quickstart
```bash
docker compose up --build
curl -s http://localhost:8000/health | jq
```

## Demo
```bash
# PII redaction
docker compose up -d
curl -s -X POST http://localhost:8000/guardrail/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"text":"Email me at jane.doe@example.com"}' | jq
```

## Integration Modes

* **Proxy:** Point your app’s OpenAI client at this service’s OpenAI-compatible routes.
* **Library:** Import and call evaluation functions directly within your Python app.

See `docs/INTEGRATION.md` for code examples and route mapping.

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

To avoid high-cardinality route labels in the latency histogram, clamp raw paths
with the helper:

```python
from app.metrics.route_label import route_label

safe_route = route_label(request.url.path)
hist.labels(route=safe_route, method=request.method).observe(latency)
```

Audit events include tenant_id, bot_id, request_id, policy version, bytes, hashes, and meta.client.

Examples

Use the runnable scripts in examples/curl/:

chat.sh, completions.sh, embeddings.sh, moderations.sh

images_generations.sh, images_edits.sh, images_variations.sh

Set API_BASE and headers in each script (see comments) or export from environment.

Environment

See .env.example for all keys and defaults.

### Clarify vs Block defaults

By default, the Guardrail API **blocks** injection/jailbreak attempts.
Switch baseline to **clarify** with:

```bash
export POLICY_DEFAULT_INJECTION_ACTION=clarify
```

Per-rule `on_match` still takes precedence. If no rule sets an action,
the default above is applied.

### Verifier (MVP)
Enable a non-executing intent verifier for gray-area cases (injection/jailbreak/illicit families).

```bash
export VERIFIER_ENABLED=true
export VERIFIER_PROVIDER=mock   # or openai|anthropic|azure (future)
```

Behavior: if a request hits gray families and the local decision isn’t decisive, the API calls the
verifier, which returns `block | clarify | allow`. A minimal trace appears under `debug.verifier`.

### Compliance (Phase 2)
- Hashing helpers (email/phone) via salted SHA-256: `PII_SALT`, `PII_HASH_ALGO`.
- Redact + hash utility: `app/compliance/pii.py`.
- Admin endpoints:
  - `GET /admin/compliance/status`
  - `POST /admin/compliance/hash` (fields: `email`, `phone`, `text`)
- Retention knob (policy-level): `DATA_RETENTION_DAYS`.

**Quick try:**
```bash
curl -s localhost:8000/admin/compliance/status | jq
curl -s -X POST localhost:8000/admin/compliance/hash \
  -H 'Content-Type: application/json' \
  -d '{"text":"email a@b.co, phone 555-123-4567"}' | jq
```

Testing
ruff check --fix .

### Debugging provenance (X-Debug)

Add the header `X-Debug: 1` to any request to receive a structured `debug.sources` array:

```json
{
  "debug": {
    "sources": [
      {
        "origin": "ingress",
        "modality": "text",
        "filename": null,
        "mime_type": "text/plain",
        "size_bytes": 42,
        "sha256": "…",
        "rule_hits": {"pii:email": ["…"]},
        "redactions": [{"start": 11, "end": 27, "label": "[REDACTED:EMAIL]"}]
      }
    ]
  }
}
```

Raw content is never included in debug; only fingerprints and spans are returned.
mypy .
pytest -q


All tests must be green before merge.
