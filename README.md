# llm-guardrail-api-next

A minimal, working FastAPI starter for your Guardrail API. Includes:
- App factory with `/healthz`, `/metrics`, and `/guardrail`
- Stub policy pipeline (always allow) wired to YAML rules
- Pydantic v2 settings, Prometheus metrics
- GitHub Actions: `preflight` (env sanity) + `ci` (lint/tests)

## Run locally
Use any runner you like (uvicorn, docker). Environment keys live in `.env`.

## Endpoints
- `GET /healthz` — liveness/readiness
- `GET /metrics` — Prometheus exposition
- `POST /guardrail` — classify/allow/transform (stubbed to ALLOW)

## Tests
`pytest -q`

## Next steps
- Replace `app/services/upipe.py` with your real pipeline
- Expand `app/services/policy.py` with actual decisions & transforms
- Flesh out rules in `app/policy/rules.yaml`
