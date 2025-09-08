# Guardrail Observability

This package gives you:
- **PromQL cookbook** for your dashboards/alerts.
- **Grafana dashboards** you can import as-is.
- **Prometheus scrape examples** (vanilla + Prometheus Operator).

> No code changes required. Metrics are scraped from `/metrics`.

---

## 1) Scrape setup

### Vanilla Prometheus
Use `docs/observability/prometheus-scrape.yml` as a starting point:
```yaml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'guardrail-api'
    metrics_path: /metrics
    static_configs:
      - targets: ['guardrail.default.svc.cluster.local:8000'] # adjust
```

### Prometheus Operator (Kubernetes)

Apply `k8s/servicemonitor-guardrail.yaml` and ensure your Service has the label `app: guardrail-api`, or adjust the selector accordingly.

## 2) Import dashboards

Import the JSON files in `observability/grafana/`:

- `Guardrail_Overview.json` — traffic, decisions, redactions, tenants/bots, PDF-hidden detections.
- `Verifier_Details.json` — sampling vs trigger, errors, latency.
- `Quota_and_Rate_Limits.json` — optional if you export those metrics.

Each panel uses PromQL that matches exposed counters such as:

- `guardrail_decisions_total`
- `guardrail_decision_family_tenant_bot_total`
- `guardrail_redactions_total`
- `guardrail_pdf_hidden_total{reason=...}`
- *(optional)* `guardrail_verifier_*` if you emit verifier metrics

If some series are absent, panels will just render empty (safe).

## 3) What the key metrics mean

`guardrail_decisions_total{family}`
: Count of ingress/egress decisions, normalized to families like allow, sanitize, deny.

`guardrail_decision_family_tenant_bot_total{tenant,bot,family}`
: Same, but with tenant/bot breakdown.

`guardrail_redactions_total{direction}`
: Number of redactions applied, labeled by `direction = ingress` or `egress`.

`guardrail_pdf_hidden_total{reason}`
: Hidden text detector reasons seen in PDFs (e.g., `white_nonstroke_color`, `tiny_font`).

`guardrail_verifier_` *(optional)*

- `guardrail_verifier_invocations_total`
- `guardrail_verifier_skipped_total{reason}`
- `guardrail_verifier_errors_total{kind}`
- `guardrail_verifier_latency_ms_*` (histogram)

## 4) Useful queries

See `docs/observability/promql.md` for copy-paste PromQL you can use in custom dashboards and alerts.
