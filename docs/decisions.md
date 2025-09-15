# Decision Headers & Escalation

Every `/guardrail/evaluate` response now includes standard Guardrail headers:

- `X-Guardrail-Decision`: `allow` or `deny`
- `X-Guardrail-Mode`: `normal`, `execute_locked`, or `full_quarantine`
- `X-Guardrail-Incident-ID`: UUID v4 per request
- `X-Guardrail-Policy-Version`: currently loaded rules version
- Optional: `X-Guardrail-Rule-IDs`: CSV of matched rule identifiers when available
- `X-Request-ID`: propagated from the inbound request or generated when absent

These headers are emitted for both success and error responses, allowing operators to
correlate API activity with telemetry, audit logs, and support tickets.

## Escalation (optional)

Guardrail tracks deny strikes per request fingerprint (tenant, bot, user agent,
API key, and source IP hashed with a pepper). When escalation is enabled and the
deny threshold is exceeded within the configured window, Guardrail escalates the
actor into **full_quarantine**, returning HTTP **429** alongside a `Retry-After`
header. Subsequent requests from the fingerprint remain quarantined until the
cooldown elapses.

Enable escalation with environment variables:

```
ESCALATION_ENABLED=true
ESCALATION_DENY_THRESHOLD=3
ESCALATION_WINDOW_SECS=300
ESCALATION_COOLDOWN_SECS=900
ESCALATION_HASH_PEPPER=optional-secret-pepper
```

With the configuration above, three deny decisions within five minutes place the
fingerprint into quarantine for fifteen minutes. The `X-Guardrail-Mode`
header reports `full_quarantine` and clients receive a `Retry-After` hint for
backoff. Because fingerprints use a peppered hash, no raw identifiers are
emitted in metrics or logs.
