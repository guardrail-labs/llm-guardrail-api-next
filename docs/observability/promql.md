# PromQL Cookbook

## Traffic & Decisions

**Requests by decision family**
```promql
sum by (family) (rate(guardrail_decisions_total[5m]))
```

**Top tenants/bots (last 5m)**
```promql
topk(10, sum by (tenant, bot) (rate(guardrail_decision_family_tenant_bot_total[5m])))
```

## Redactions

**Redactions by direction**
```promql
sum by (direction) (rate(guardrail_redactions_total[5m]))
```

**Estimated redaction rate**
```promql
sum(rate(guardrail_redactions_total[5m])) /
sum(rate(guardrail_decisions_total[5m]))
```

## PDF Hidden Text

**Detections by reason**
```promql
sum by (reason) (rate(guardrail_pdf_hidden_total[5m]))
```

## Verifier (if exported)

**Invocations vs skipped**
```promql
rate(guardrail_verifier_invocations_total[5m])
```
```promql
sum by (reason) (rate(guardrail_verifier_skipped_total[5m]))
```

**Errors by kind**
```promql
sum by (kind) (rate(guardrail_verifier_errors_total[5m]))
```

**Latency P95**
```promql
histogram_quantile(
  0.95,
  sum by (le) (rate(guardrail_verifier_latency_ms_bucket[5m]))
)
```

## SLO-ish Views

**Sanitize share of decisions**
```promql
sum(rate(guardrail_decisions_total{family="sanitize"}[5m])) /
sum(rate(guardrail_decisions_total[5m]))
```

**Deny rate**
```promql
sum(rate(guardrail_decisions_total{family="deny"}[5m])) /
sum(rate(guardrail_decisions_total[5m]))
```
