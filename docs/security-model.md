# Security model

## Threat-informed goals
- **Block disallowed content** before it reaches end users or downstream systems.
- **Auditability** of each decision with stable identifiers (incident/request IDs).
- **Org controls** for explicit overrides with visibility (metrics/webhooks).

## Enforcement posture
The Guardrail API enforces policy synchronously around model I/O.  
When policies are active, disallowed outputs are intercepted and replaced with the configured
mitigation outcome. The original disallowed output is not returned to the client.

This posture provides strong defaults, but it is not a blanket guarantee:
- If a pack is missing or disabled, the API cannot block on its behalf.
- Administrators must enable and maintain the policy packs that match their compliance requirements.

## Enforcement + observability
- **In-band enforcement:** the decision engine runs synchronously around model I/O.
- **Telemetry:** Prometheus metrics for outcomes, retries, webhooks, queue depth.
- **Webhooks:** signed events on decision outcomes (v0 body HMAC or v1 ts+body).
- **Decision store:** optional SQLite/SQL store with simple query API.

## Admin / override posture
- Overrides are explicit and logged via counters and decision records.
- Force-block toggle can apply globally or to an allowlist of tenants.

## Fail-safe posture
- Circuit breakers DLQ failing webhooks; retries use decorrelated jitter.
- Non-critical observability writes use best-effort helpers; enforcement remains in-band.
