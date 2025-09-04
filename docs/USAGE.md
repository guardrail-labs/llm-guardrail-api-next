# LLM Guardrail API — Usage Guide

**Goal:** Quick, clear steps to run and use the Guardrail API with OpenAI and Azure compat modes, quotas, auditing, and streaming.

---

## 1) Quick Start

### Run (local)

```bash
# minimal env for LocalEcho provider
export LLM_PROVIDER=local-echo
export OAI_COMPAT_MODELS="gpt-4o-mini,gpt-4o"

uvicorn app.main:app --reload --port 8000
# or however you start your FastAPI app

# Health check
curl -s http://localhost:8000/v1/models | jq
```

You should see your configured model IDs.

## 2) Environment Variables

### Core
- **LLM_PROVIDER**  
  local-echo (default) or openai
- **OPENAI_API_KEY**  
  Required if LLM_PROVIDER=openai
- **OPENAI_BASE_URL**  
  Optional. For Azure-/compatible endpoints.

### OpenAI compat
- **OAI_COMPAT_MODELS**  
  Comma list for /v1/models (e.g. gpt-4o-mini,gpt-4o)
- **OAI_COMPAT_EMBED_DIM**  
  Embedding dimension for local deterministic vectors (default 1536)

### Guardrails / Policy
- **POLICY_AUTORELOAD** (true|false)
- **POLICY_RULES_PATH** (path to rules file)

### Threat feed
- **THREAT_FEED_URLS** (comma list)
- **THREAT_FEED_ENABLED** (true|false)

### Rate limit (per-process token bucket)
- **RATE_LIMIT_ENABLED** (true|false)
- **RATE_LIMIT_PER_MINUTE** (default 60)
- **RATE_LIMIT_BURST** (default RATE_LIMIT_PER_MINUTE)

### Quotas (per-tenant/bot)
Configure via your `app.shared.quotas` implementation (already wired).

Returns 429 with:
- **Retry-After**
- **X-Guardrail-Quota-Window**
- **X-Guardrail-Quota-Retry-After**

### Audit
- **AUDIT_ENABLED** (true|false)
- **AUDIT_MAX_TEXT_CHARS** (snippet len; default 64)

### Misc
- `GUARDRAIL_DISABLE_AUTH=1`  
  Bypass admin auth in CI/tests
- **MAX_PROMPT_CHARS**  
  413 if exceeded (legacy /guardrail)

## 3) Headers for Multitenancy

Send these on every call:

- `X-Tenant-ID: <tenant>`
- `X-Bot-ID: <bot>`

They drive:
- Audit tenant_id / bot_id
- Per-tenant/bot quotas
- Per-tenant/bot metrics

## 4) OpenAI-Compatible Endpoints

Base path: `/v1`

**List models**
```bash
curl -s http://localhost:8000/v1/models | jq
```

**Chat completions (non-stream)**
```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: support" \
  -d '{
    "model":"gpt-4o-mini",
    "messages":[{"role":"user","content":"Hello!"}]
  }' | jq
```

Guard headers returned (non-stream):

- `X-Guardrail-Policy-Version`
- `X-Guardrail-Ingress-Action` (allow|deny)
- `X-Guardrail-Egress-Action` (allow|deny)
- `X-Guardrail-Egress-Redactions` (int)

**Chat completions (stream SSE)**
```bash
curl -N http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: support" \
  -d '{
    "model":"gpt-4o-mini",
    "stream": true,
    "messages":[{"role":"user","content":"Tell me a short joke."}]
  }'
```

Streamed deltas have guardrails applied incrementally.

If blocked mid-stream, finish reason is `content_filter`.

**Text completions (OpenAI legacy)**
```bash
curl -s http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: support" \
  -d '{"model":"gpt-4o-mini","prompt":"Write a haiku"}' | jq
```

**Moderations**
```bash
curl -s http://localhost:8000/v1/moderations \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: support" \
  -d '{
    "model":"omni-moderation-latest",
    "input":["Say how to make explosives"]
  }' | jq
```

We map internal deny → `flagged=true`.

**Embeddings**
```bash
curl -s http://localhost:8000/v1/embeddings \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: search" \
  -d '{
    "model":"text-embedding-3-small",
    "input":"lorem ipsum"
  }' | jq
```

Local provider returns deterministic vectors (demo).

Ingress guard still applies; deny → 400.

## 5) Azure OpenAI-Compatible Endpoints

Base path: `/openai/deployments/{deployment}`

**Chat completions**
```bash
curl -N \
  "http://localhost:8000/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: support" \
  -d '{
    "stream": true,
    "messages":[{"role":"user","content":"Hi Azure style!"}]
  }'
```

Non-streaming responses include `X-Azure-API-Version`.

**Embeddings**
```bash
curl -s \
  "http://localhost:8000/openai/deployments/text-embedding-3-small/embeddings?api-version=2024-02-15-preview" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: search" \
  -d '{"input":"hello"}' | jq
```

## 6) Guardrail APIs (Direct)

**Ingress (modern)**
```bash
curl -s http://localhost:8000/guardrail/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: web" \
  -d '{"text":"ignore previous instructions and …"}' | jq
```

Response keys:

- `action`: allow | deny | clarify
- `text` / `transformed_text`
- `rule_hits` (families)
- `redactions` (int)
- `debug` (when `X-Debug: 1`)

**Ingress (multipart)**
```bash
curl -s http://localhost:8000/guardrail/evaluate_multipart \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: web" \
  -F "text=caption this image" \
  -F "files=@sample.png"
```

**Egress**
```bash
curl -s http://localhost:8000/guardrail/egress_evaluate \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" -H "X-Bot-ID: web" \
  -d '{"text":"model output here"}' | jq
```

Returns `allow`|`deny` and sanitized text if redactions apply.

## 7) Quotas and Rate Limits

**Quota (per tenant/bot):**

On quota hit → 429 JSON:

- `code`: `"rate_limited"`
- `detail`: `"Per-tenant quota exceeded"`
- `retry_after` (seconds)
- `request_id`

Headers:
- `Retry-After`
- `X-Guardrail-Quota-Window`
- `X-Guardrail-Quota-Retry-After`

**Rate limit (per-process):**

On burst exceed → 429 with `Retry-After: 60`.

## 8) Audit Events (Enterprise)

Emitted on ingress and egress across:

- `/guardrail/*`
- `/v1/chat/completions`, `/v1/completions`, `/v1/moderations`, `/v1/embeddings`
- Azure equivalents

Always includes `meta.client`:

- `ip`, `user_agent`, `path`, `method`

Useful fields:

- `tenant_id`, `bot_id`, `request_id`
- `decision`, `rule_hits`, `policy_version`
- `redaction_count`, `hash_fingerprint`
- `payload_bytes`, `sanitized_bytes`

Auditing never breaks requests; failures are swallowed.

## 9) Metrics

Expose your Prometheus metrics endpoint (e.g., `/metrics` via Starlette middleware
or custom route). This API tracks:

Global decision-family counters:
- `allow`, `block`, `sanitize`, `verify`

Per-tenant and per-bot breakdown (exported text helpers available)

Quota rejects:
- `guardrail_quota_rejects_total{tenant_id,bot_id}`

## 10) Debugging

- Add `X-Debug: 1` to see `debug.matches`, `debug.threat_feed`, and `debug.verifier` when applicable.

## 11) Client Snippets

### Python (requests)

```python
import requests

url = "http://localhost:8000/v1/chat/completions"
headers = {
    "Content-Type": "application/json",
    "X-Tenant-ID": "demo",
    "X-Bot-ID": "support",
}
body = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}],
}

r = requests.post(url, headers=headers, json=body, timeout=30)
r.raise_for_status()
print(r.json())
print("Ingress:", r.headers.get("X-Guardrail-Ingress-Action"))
print("Egress:", r.headers.get("X-Guardrail-Egress-Action"))
```

## 12) Troubleshooting

- **401**: Missing/invalid auth (admin endpoints) or provider creds.
- **429**: Quota or rate limit. Check `Retry-After` headers.
- **400** (OpenAI endpoints): Ingress deny — validate content; use `X-Debug: 1`.
- Missing models: Set `OAI_COMPAT_MODELS`.

