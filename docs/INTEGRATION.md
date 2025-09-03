# Integration

## Proxy Mode (OpenAI compatible)

Point your OpenAI client to the Guardrail API. Example (Python):

```python
import openai
openai.api_base = "http://localhost:8000/v1"  # Guardrail
openai.api_key = "sk-placeholder"

# normal OpenAI call, Guardrail sits in front
resp = openai.ChatCompletion.create(
    model="gpt-4o-mini", messages=[{"role":"user","content":"Hello"}]
)
```

## Library Mode

```python
from app.services.detectors import evaluate_prompt

result = evaluate_prompt(text="Hello world")
print(result["action"], result.get("text"))
```

## Guardrail Routes

* `POST /guardrail/evaluate` (ingress)
* `POST /guardrail/egress_evaluate` (egress)
* `GET  /health`
* `GET  /metrics` (Prometheus)
