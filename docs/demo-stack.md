# Demo Stack (Docker Compose)

Spin up the Guardrail API + Prometheus + Grafana with one command.

## Start

```bash
make demo-stack-up


API: http://localhost:8000

Prometheus: http://localhost:9090

Grafana: http://localhost:3000
 (admin/admin)

Grafana auto-loads the dashboard from observability/grafana/guardrail.json.
```

## Generate Traffic

```bash
make demo-stack-traffic
```

This seeds allow/deny decisions so panels/alerts have data.

## Stop / Clean

```bash
make demo-stack-down
make demo-stack-clean  # also removes volumes
```

Tip: You can still use the Admin UI at http://localhost:8000/admin/ui
 (Bearer demo).

