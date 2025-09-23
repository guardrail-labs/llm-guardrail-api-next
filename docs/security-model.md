# Security model

## Threat-informed goals
- **Block disallowed content** before it reaches end users or downstream systems.
- **Auditability** of each decision with stable identifiers (incident/request IDs).
- **Org controls** for explicit overrides with visibility (metrics/webhooks).

## Core guarantee
If a model attempts to produce content that violates your policy/statute, the Guardrail API enforces the decision (e.g., `block`, `clarify`, `redact`) **in-band**, and the original disallowed output **does not reach** the user. The client receives a mitigated response with decision context for observability.

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
