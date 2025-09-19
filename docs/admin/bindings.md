# Admin Bindings

## Golden policy binding

`POST /admin/bindings/apply_golden` applies the built-in Golden policy pack
(PII + Secrets) to a specific tenant and bot. The endpoint is idempotent and is
protected by the standard admin authentication.

The policy file is resolved from the `GOLDEN_POLICY_PATH` environment variable.
If the variable is unset, the service defaults to
`rules/policies/golden/default.yaml`. The request fails with `404` when the
resolved file cannot be read.

## Strict secrets binding

`POST /admin/bindings/apply_strict_secrets` applies the built-in Strict Secrets
policy pack to a specific tenant and bot. The endpoint mirrors the Golden
binding flow and refreshes the in-memory binding cache even when already bound
to the strict policy.

The policy file is resolved from the `STRICT_SECRETS_POLICY_PATH` environment
variable. If the variable is unset, the service defaults to
`rules/policies/secrets/strict.yaml`. The request fails with `404` when the
resolved file cannot be read.

## Demo defaults binding

`POST /admin/bindings/apply_demo_defaults` applies the built-in Demo Defaults
policy pack to a specific tenant and bot. The endpoint mirrors the Golden and
Strict Secrets flows and refreshes the in-memory binding cache even when the
binding already targets the demo policy.

The policy file is resolved from the `DEMO_POLICY_PATH` environment variable.
If the variable is unset, the service defaults to
`rules/policies/demo/default.yaml`. The request fails with `404` when the
resolved file cannot be read.
