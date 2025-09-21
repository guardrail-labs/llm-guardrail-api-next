# Operations Quickstart

Use these probes and dashboards to confirm the deployment is healthy.

## Probes

* `GET /healthz` – dependency self-test. Fails when critical services (policy load, Redis, filesystem) are down.
* `GET /readyz` – readiness gate. Fails on policy sync errors, DLQ backlog, or when mitigation/audit stores are unavailable.

## Metrics Highlights

Key Prometheus signals exported from `/metrics`:

* `readyz_status{component="redis"}` – `0` when Redis is unhealthy, `1` when normal.
* `readyz_status{component="dlq"}` – `1` indicates the DLQ has backlog requiring intervention.
* `admin_override_total` – gauge of active override policies.
* `dlq_depth` – depth of the webhook dead-letter queue; anything above 10 for >5m is actionable.

## Dashboards & Assets

Grafana and Prometheus assets live at:

* `ops/prometheus/*` – scrape configs and custom rules.
* `ops/grafana/*` – importable dashboards.

Load them into your observability stack for parity with staging.
