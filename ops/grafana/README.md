# Grafana Dashboards & Alerts (Core)

**Data source:** Prometheus (named `Prometheus` in Grafana).

## Import
1. Open Grafana → Dashboards → Import.
2. Upload each JSON from `ops/grafana/dashboards`.
3. Set folder to `Guardrail / Core`.
4. Repeat for alert rule JSONs under `ops/grafana/alerts`:
   - Alerting → Alert rules → Import.

## Panels reference metrics
- `guardrail_sanitizer_events_total{tenant,type}`
- `guardrail_sanitizer_actions_total{tenant,action}`
- `guardrail_verifier_events_total{provider,event}`
- Optional (placeholder): `guardrail_dlq_messages{queue}`

> If your Prometheus label names differ, edit queries inline after import.

## Runbook (high level)
- **Block-rate spike** → Check `X-Guardrail-Policy` / `Sanitizer` headers in logs,
  confirm a bad input burst vs. mis-tuned policy. If benign traffic, raise
  `max_confusables_ratio` by +0.01 (PR-007 tuner).
- **Verifier outage** → Look at `providers` panel. If all down, manager should
  default-block with incident IDs. Rotate provider keys, check upstream health.
- **Oversize skips** → Potential DoS via large uploads. Verify CDN limits/WAF and
  consider reducing `max_bytes` in `MultimodalFlags`.
