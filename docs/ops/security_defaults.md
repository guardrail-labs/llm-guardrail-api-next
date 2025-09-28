# Guardrail Security Defaults (Ops Profile)

## Goals
Safe defaults that surface issues first, then allow enforcement by tenant.

## Recommended config (start in staging)
- ingress_duplicate_header_guard_mode: "log"
- ingress_duplicate_header_unique:
  - content-length, transfer-encoding, host, authorization,
    x-request-id, traceparent, x-guardrail-tenant, x-guardrail-bot
- ingress_duplicate_header_metric_allowlist:
  - above + content-type, accept, cookie, set-cookie
- ingress_header_limits_enabled: true
  - ingress_max_header_count: 200
  - ingress_max_header_value_bytes: 8192
- ingress_unicode_sanitizer_enabled: true
- ingress_unicode_enforce_mode: "log"
- ingress_unicode_enforce_flags: ["bidi","zwc"]
- egress inspector/redactor: use repo defaults; no Content-Length on streams

## Rollout steps
1. Enable **log** modes in staging; watch dashboards/alerts for 48–72h.
2. Tune allowlists/thresholds per tenant if noisy.
3. Flip to **block** for duplicate headers, then unicode (`bidi|zwc`) if needed.
4. Lock perf bench baseline when stable (see docs/observability/perf.md).

## Alerts & dashboards
- Duplicate headers: deploy/prometheus/alerts_duplicate_headers.yaml
- Header limits: deploy/prometheus/alerts_header_limits.yaml
- Trace guard: deploy/prometheus/alerts_trace_guard.yaml
- Dashboard: deploy/grafana/guardrail_security_overview.json

## Runbooks
- See docs/observability/alerts.md sections for each alert family.
