# Operator Guide

This covers runtime knobs: policies, bindings, verifier, threat feed, metrics.

## Policies

- Default rules are bundled at `app/policy/rules.yaml`.
- You can point to a custom file via env:
  - `POLICY_RULES_PATH=/absolute/path/to/rules.yaml`
  - `POLICY_AUTORELOAD=true` enables live reload when the file changes.

Reload via API (both update the same source used by enforcement):
```bash
curl -fsS -X POST http://localhost:8080/admin/policy/reload | jq .
# or
curl -fsS -X POST http://localhost:8080/admin/policy/reload | jq .
```

Per-tenant/bot bindings

Bind {tenant, bot} to a specific rules.yaml without changing envs.

Endpoints (require X-Admin-Key, if configured):

```bash
# List
curl -fsS -H "X-Admin-Key: $(grep ADMIN_API_KEY .env|cut -d= -f2)" \
  http://localhost:8080/admin/bindings | jq .

# Put/update (exact match or wildcards: tenant="*", bot="*")
curl -fsS -X PUT -H "Content-Type: application/json" \
  -H "X-Admin-Key: $(grep ADMIN_API_KEY .env|cut -d= -f2)" \
  -d '{"tenant":"acme","bot":"*","rules_path":"/mnt/shared/policies/acme.yaml"}' \
  http://localhost:8080/admin/bindings | jq .

# Delete
curl -fsS -X DELETE -H "X-Admin-Key: $(grep ADMIN_API_KEY .env|cut -d= -f2)" \
  "http://localhost:8080/admin/bindings?tenant=acme&bot=*" | jq .
```

At request time, enforcement resolves policy in priority order:

Binding match for {tenant, bot} (exact beats wildcard)

POLICY_RULES_PATH (env override)

Bundled default (app/policy/rules.yaml)

Send headers X-Tenant-ID and X-Bot-ID with requests to select the binding.

Verifier

Toggle gray-area routing:

verifier_enabled=true

verifier_provider=mock|openai|anthropic|azure

verifier_default_action=block|clarify

The API routes “uncertain” prompts based on families (e.g., injection/jailbreak).

Threat feed (dynamic redactions)

Enable with THREAT_FEED_ENABLED=1

Provide comma-separated THREAT_FEED_URLS of JSON specs:

{
  "version": "2024-09-01",
  "redactions": [
    {"pattern": "Bearer [A-Za-z0-9_-]{20,}", "tag": "secrets:vendor_token", "replacement": "[REDACTED:VENDOR_TOKEN]"}
  ]
}

Metrics & dashboards

Prometheus scrapes api:8000/metrics and audit-receiver:8079/metrics.

Key metrics:

Decision families (ingress/egress) by tenant/bot

Redactions by mask (directional)

Quota rejections

Grafana: “Guardrail Overview” is preprovisioned.

OCR (multimodal)

OCR_ENABLED=1 will OCR images/PDFs in multipart uploads and feed extracted text through the same pipeline.

With OCR off, behavior is unchanged.

