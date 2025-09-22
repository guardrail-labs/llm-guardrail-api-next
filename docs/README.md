# LLM Guardrail API Ops Bundle

This service brokers guardrail policies, enforcement, and admin tooling for LLM surfaces. Use this bundle for day-to-day operations, smoke validation, and configuration lookups.

## Quick Smoke Checklist

Run the following from the repo root after updating dependencies or infrastructure:

```bash
ruff check --fix .
mypy .
pytest -q
scripts/smoke.sh
```

## Next Steps

* [Operations Quickstart](./ops-quickstart.md) – probes, metrics, and dashboards to watch.
* [Configuration Matrix](./config-matrix.md) – environment variables and their effects.
* [Alert Runbook](./runbook-alerts.md) – actionable playbooks when alerts fire.

## Operability
- [SLOs & SLIs](./operability/SLOs.md)
- Runbooks: [DLQ](./operability/runbooks/DLQ.md), [Readiness](./operability/runbooks/Readiness.md)
- Prometheus rules: `deploy/monitoring/prometheus/rules/`
- Alertmanager routes: `deploy/monitoring/alertmanager/alertmanager.yaml`

## API Reference
- [Admin API (endpoints, pagination, exports)](./api/README.md)
