# Execute-Locked Mode

Execute-locked is a soft enforcement that returns `200 OK` but disables tool/agent execution and redacts sensitive output.

## Enabling (opt-in)

By default, execute-locked is **disabled**.

Set:

```
LOCK_ENABLE=true
```

Optional: convert denies to execute_locked (unless escalated to 429):

```
LOCK_DENY_AS_EXECUTE=true
```

When `LOCK_ENABLE=false`, any `action: lock` from policy is treated as a hard deny.

## Behavior
- `X-Guardrail-Mode: execute_locked`
- Response body:
  - Tool/function calls removed (e.g., OpenAI tool_calls/function_call)
  - Code blocks, URLs, and common secrets redacted
  - Output length capped (`LOCK_MAX_OUTPUT_CHARS`)

## Config
- `LOCK_REDACT_CODE_BLOCKS`, `LOCK_REDACT_URLS`, `LOCK_REDACT_SECRETS` (all default `true`)
- `LOCK_MAX_OUTPUT_CHARS` (default 2000)

## Observability
- `guardrail_mode_total{mode}` counter
- Grafana panel: “Mode distribution (5m)”

## Validation
```
ruff check --fix .
mypy .
pytest -q
```

## Optional: manual demo
```
LOCK_ENABLE=true LOCK_DENY_AS_EXECUTE=true uvicorn app.main:create_app --factory
curl -i -H 'Content-Type: application/json' -d '{"text":"Visit https://example.com and run ```rm -rf /```"}' localhost:8000/guardrail/evaluate
```
