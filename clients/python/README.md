# Guardrail API Python SDK

A lightweight, typed wrapper around the LLM Guardrail API using [`httpx`](https://www.python-httpx.org/).

## Installation

```bash
pip install -e .
```

From the repo root you can instead install in editable mode:

```bash
pip install -e clients/python
```

## Usage

```python
import os
from guardrail_api import GuardrailClient

client = GuardrailClient(
    base_url=os.environ.get("GUARDRAIL_BASE_URL", "http://localhost:8000"),
    token=os.environ.get("GUARDRAIL_API_TOKEN"),
)

# Health checks
print(client.healthz())
print(client.readyz())

# Decisions
page = client.list_decisions(limit=5)
for item in page["items"]:
    print(item["id"], item["outcome"])

# Export adjudications as NDJSON
print(client.export_adjudications(tenant="tenant-123"))
```

Set `GUARDRAIL_API_TOKEN` to a valid API token (or leave unset when running
without authentication locally).
