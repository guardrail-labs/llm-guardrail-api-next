# Override Mitigations Runbook

The Admin Dashboard shows three override tiles that surface how many decisions relied on
per-tenant mitigation overrides since the API process started. They reflect the values of
Prometheus counter `guardrail_mitigation_override_total{mode="block|clarify|redact"}`.
Spikes in these numbers can indicate configuration drift or unexpected behavior in
recent releases.

## Typical Causes of Spikes

- **Operator toggled a tenant/bot override to block.** Expect `block` to grow quickly as
  every decision honors the override.
- **Golden Pack application.** Enabling strict packs often introduces clarify-first or
  redact overrides for testing tenants.
- **Policy or binding changes.** Updating policies can cause clarifications to fall back to
  overrides while rules warm up.
- **Incident response flags.** Temporary emergency toggles such as `FORCE_BLOCK_TENANT`
  or per-tenant safety switches will push the counters higher.

## Quick Checks

1. Inspect `guardrail_mitigation_override_total{mode="<mode>"}` in Grafana to confirm the
   magnitude and slope of the increase.
2. Compare against `guardrail_decisions_total{outcome}` to see whether the override spike
   aligns with overall decision volume or a single outcome.
3. Review the admin audit log for recent mitigation changes made by operators.
4. Verify that `FORCE_BLOCK_TENANT` and similar kill-switch flags are not accidentally set.
5. If a new deployment rolled out, review release notes or diff the mitigation override
   configuration for the affected tenants.
