# Python Client Quickstart

```python
from clients.python.guardrail_client import GuardrailClient

client = GuardrailClient(
    base_url="http://localhost:8080",
    api_key="dev-local-key",  # or production key
    use_bearer=False,          # set True to send Authorization: Bearer <key>
)

result = client.guardrail("Hello, world!")
print(result)
# {
#   'request_id': '...',
#   'decision': 'allow',
#   'reason': 'No risk signals detected',
#   'rule_hits': [],
#   'transformed_text': 'Hello, world!',
#   'policy_version': '2'
# }

client.close()
```
