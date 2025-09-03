# Configuration

## Environment
See `.env.example` for all variables. Key ones:

- `POLICY_DEFAULT_INJECTION_ACTION` (default `block`)
- `RULES_PATH` (default `/etc/guardrail/rules.yaml`)
- `MODEL_BACKEND` = `openai|anthropic|azure|local`
- Provider keys/endpoints as needed per backend

## Rules
Mount a `rules.yaml` and set `RULES_PATH` accordingly. Example minimal rules are in `rules.yaml`.

## Backend Mapping
Implementations live in `app/services/llm_client.py` (or your equivalent). The `MODEL_BACKEND`
value selects the active provider.
