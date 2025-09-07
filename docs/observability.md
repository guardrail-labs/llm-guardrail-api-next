# Observability: Audit Forwarder / Receiver & Guardrails

This document explains how to monitor the audit pipeline and guardrail decisions, run nightly smokes, and interpret alerts/SLOs.

## What’s instrumented

- **Forwarder health:** `audit_forwarder_requests_total{result="success|failure"}`
- **Guardrail decisions:** `guardrail_decisions_family_total{family=allow|sanitize|block|verify}`
- **Tenant breakdown:** `guardrail_decisions_family_tenant_total{tenant, family}`
- (Receiver exposes app metrics if configured; not required for this dashboard)

## Dashboard

Import `monitoring/grafana/dashboards/audit_forwarder.json` into Grafana.
It presents:
- **Forwarder Failure Rate (5m)** — % of failed posts in the last 5 minutes
- **Requests by Result** — success/failure over time
- **Guardrail Decisions by Family (1h)** — volume by allow/sanitize/block/verify
- **Top Tenants (1h)** — which tenants drive decisions

## Nightly smoke

A scheduled workflow exercises the receiver with a signed, idempotent request:
- File: `.github/workflows/audit-smoke-nightly.yml`
- It calls `scripts/audit/prod_smoke.sh`.

### Required GitHub repo secrets

| Secret                | Description                                |
|-----------------------|--------------------------------------------|
| `AUDIT_SMOKE_ENABLED` | Set to `1` to enable nightly smoke         |
| `AUDIT_FORWARD_URL`   | e.g., `https://receiver.example.com/audit` |
| `AUDIT_FORWARD_KEY`   | Receiver’s API key                         |
| `AUDIT_HMAC_SECRET`   | Shared HMAC secret                         |

## SLOs and Alerts

**SLO (forwarder):** failure rate **< 1%** over 30 days.  
**Page** if failure rate **> 5%** for 5 minutes.  
**Ticket** if failure rate **> 1%** for 1 hour.

PromQL reference used by dashboard:
```promql
100 * sum(rate(audit_forwarder_requests_total{result="failure"}[5m]))
  / clamp_min(sum(rate(audit_forwarder_requests_total[5m])), 1e-9)
```

If you manage alert rules in Prometheus/Alertmanager, wire the above into:

Critical: >5% for 5m

Warning: >1% for 60m

Runbook

Operational steps (setup, smoke testing, alerting, secret rotation, troubleshooting) are covered in the repo’s runbook (see docs/operations/*). If a forwarder outage occurs:

Check the failure rate panel.

Validate nightly smoke logs in Actions.

Confirm receiver is healthy and secrets (API key + HMAC) are correct.

Rotate the HMAC secret if compromise is suspected; update both forwarder and receiver.


---
