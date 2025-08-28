# LLM Guardrail API

FastAPI middleware that evaluates and sanitizes prompts before they reach your LLM, with reloadable policy, redactions, and Prometheus metrics.

## Quickstart
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI docs: http://localhost:8000/docs

## API Contracts

### `GET /health`

**Response**

```json
{
  "ok": true,
  "status": "ok",
  "requests_total": 0,
  "decisions_total": 0,
  "rules_version": "string"
}
```

### `GET /metrics`

Prometheus exposition includes at least:

- `guardrail_requests_total`
- `guardrail_decisions_total`
- `guardrail_redactions_total`
- `guardrail_audit_events_total`
- `guardrail_latency_seconds_count`
- `guardrail_latency_seconds_sum`

### `POST /guardrail/evaluate`

**Request**

```json
{ "text": "your prompt", "request_id": "optional-guid" }
```

**Response**

```json
{
  "request_id": "guid",
  "action": "allow",
  "transformed_text": "possibly redacted text",
  "decisions": [{ "type": "redaction", "changed": true }]
}
```

### `POST /admin/policy/reload`

In production, requires `X-API-Key` (tests/CI bypass via `GUARDRAIL_DISABLE_AUTH=1`).

**Response**

```json
{ "reloaded": true, "version": "string", "rules_loaded": 0 }
```

## Environment

- `CORS_ALLOW_ORIGINS` — comma-separated origins; empty means CORS disabled.
- `GUARDRAIL_DISABLE_AUTH` — set `1` in tests/CI to bypass admin auth.
- `GUARDRAIL_RULES` — path to a `rules.yaml` file.

## Minimal Python client

```python
from clients.python.guardrail_client import GuardrailClient

with GuardrailClient("http://localhost:8000", api_key="test") as c:
    resp = c.evaluate("hello sk-ABC...")
    print(resp["action"], resp["transformed_text"])
```

## Releasing

See [RELEASING.md](RELEASING.md).

