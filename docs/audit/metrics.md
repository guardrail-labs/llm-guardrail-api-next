# Metrics

## Forwarder (app)
- `audit_forwarder_requests_total{result="success|failure"}` – deliverability
- Decision families (from guardrail):
  - `guardrail_decisions_family_total{family="allow|sanitize|block|verify"}`
  - `guardrail_decisions_family_tenant_total{tenant, family}`
  - `guardrail_decisions_family_bot_total{tenant, bot, family}`
- Redactions:
  - `guardrail_redactions_total{mask="email|phone|openai_key|aws_access_key_id|private_key|..."}`
- Versions:
  - `guardrail_requests_total`, `guardrail_decisions_total`, `guardrail_latency_seconds`

## Receiver
- Expose analogous counters for accepts, signatures failed, stale timestamps, and idempotent replays (names may vary per implementation).

### Quick checks
- Alert if `audit_forwarder_requests_total{result="failure"}` spikes
- Track tenant/bot hot spots via family breakdown
