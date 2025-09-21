# Operations Quickstart

Use these probes and dashboards to confirm the deployment is healthy.

## Probes

* `GET /healthz` – dependency self-test. Fails when critical services (policy load, Redis, filesystem) are down.
* `GET /readyz` – readiness gate. Fails on policy sync errors, DLQ backlog, or when mitigation/audit stores are unavailable.

## Metrics Highlights

Key Prometheus signals exported from `/metrics`:

* `readyz_status{component="redis"}` – `0` when Redis is unhealthy, `1` when normal.
* `readyz_status{component="dlq"}` – `1` indicates the DLQ has backlog requiring intervention.
* `admin_override_total` – gauge of active override policies.
* `dlq_depth` – depth of the webhook dead-letter queue; anything above 10 for >5m is actionable.

## Dashboards & Assets

Grafana and Prometheus assets live at:

* `ops/prometheus/*` – scrape configs and custom rules.
* `ops/grafana/*` – importable dashboards.

Load them into your observability stack for parity with staging.

## Admin OIDC SSO

Set these environment variables to enable admin single sign-on with an OIDC provider such as Okta, Azure AD, or GitHub:

```
OIDC_ENABLED=true
OIDC_ISSUER=https://dev-XXXX.okta.com/oauth2/default
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_SCOPES=openid email profile
OIDC_ROLE_CLAIM=groups
OIDC_ROLE_MAP={"admin":["guardrail-admin"],"operator":["guardrail-ops"],"viewer":["guardrail-viewer"]}
```

Register the redirect URI `https://<host>/admin/auth/callback` with the provider. Map group/role claims to `admin`, `operator`, or `viewer` using `OIDC_ROLE_MAP`. The admin UI and API share the same cookie-backed session and continue to honor CSRF protections and legacy bearer/basic tokens.
