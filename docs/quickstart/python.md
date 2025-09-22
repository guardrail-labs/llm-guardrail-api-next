# Guardrail API quickstart (Python)

Use the lightweight SDK located in `clients/python`.

## Setup

```bash
pip install -e clients/python
```

Set your environment variables:

```bash
export GUARDRAIL_BASE_URL="http://localhost:8000"
export GUARDRAIL_API_TOKEN="YOUR_TOKEN"
```

## Example

```python
import os
from guardrail_api import GuardrailClient

client = GuardrailClient(
    os.environ.get("GUARDRAIL_BASE_URL", "http://localhost:8000"),
    token=os.environ.get("GUARDRAIL_API_TOKEN"),
)

print("health", client.healthz())
print("ready", client.readyz())

page = client.list_decisions(limit=5)
for decision in page["items"]:
    print(decision["id"], decision["outcome"])

ndjson = client.export_adjudications(tenant="tenant-123")
print(ndjson.splitlines()[0])
```

When scoping is enforced server-side you can omit the `tenant`/`bot` arguments
and the API will derive them from your session or API token.
