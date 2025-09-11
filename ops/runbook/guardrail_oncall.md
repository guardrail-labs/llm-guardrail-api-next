# Guardrail On-call Runbook

## Overview
This runbook covers common alerts for the Guardrail service and how to triage them.

## Immediate Checks
- `curl http://<service>/healthz` to confirm status and feature flags.
- Open the *Guardrail Overview* Grafana dashboard.
- Review stat panels for fallback ratio, deny ratio, redactions/1k, and verifier p95.

## Triage
### Deny ratio spike
- Check recent policy changes or rules reloads.
- Confirm that traffic patterns look normal.

### Fallback ratio spike
- Inspect verifier provider health and error kinds.
- Verify environment overrides for fallback behaviour.

### Redactions surge
- Look for leaked tokens in upstream payloads or tenant activity.

### Verifier latency increase
- Inspect verifier p95 panel and sampling percentage.

## Mitigations
- Lower `VERIFIER_SAMPLING_PCT`.
- Temporarily raise `VERIFIER_LATENCY_BUDGET_MS`.
- Set `VERIFIER_ERROR_FALLBACK=allow` if the provider is down.

## Capturing Context
- Take screenshots of panels and note relevant PromQL.
- Link to the dashboard and attach policy version from `/healthz`.

## Escalation
- Page service owners if mitigation fails.
- Escalate to platform SRE for infrastructure issues.
