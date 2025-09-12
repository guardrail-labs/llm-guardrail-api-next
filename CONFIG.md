# Guardrail Service – Configuration Reference

This document lists all environment variables that configure runtime behavior. Values
are parsed and normalized via `app/services/config_sanitizer.py`.

> **Defaults**: If a var is missing or invalid, the sanitizer applies the default
> and clamps into safe ranges as noted below.

## Verifier

| Name                         | Type    | Default | Allowed Range   | Examples                  | Notes |
|------------------------------|---------|---------|-----------------|---------------------------|-------|
| `VERIFIER_LATENCY_BUDGET_MS` | int/ms  | *unset* | > 0 (ms); else unset | `200`, `200.5`, `200ms` | Missing/≤0/NaN/alpha ⇒ **unset** (no budget).
| `VERIFIER_SAMPLING_PCT`      | float   | `0.0`   | `0.0`–`1.0`     | `0`, `0.25`, `1`, `0.333` | Bad input clamped into range; alpha ⇒ `0.0`.

### Behavior
- **Latency budget**: If unset, the verifier path runs without a hard per-request budget.
- **Sampling percent**: Fraction of requests sampled for verification. `0.0` disables.

## Boot Snapshot (optional)
On startup, you may log a one-line snapshot of normalized config values using
`ConfigSnapshot.capture().as_kv()` from `config_sanitizer`.

```
from app.services.config_sanitizer import ConfigSnapshot
snap = ConfigSnapshot.capture()
print("CONFIG:", ", ".join(f"{k}={v}" for k, v in snap.as_kv()))
```

### Verifier Runtime Behavior
- Latency budget is enforced around verifier calls using an asyncio timeout.
- On timeout, the adapter returns an allowed outcome with reason
  `verifier_timeout_budget_exceeded` (policy layer may change final action).

### Observability
When the circuit breaker is enabled (`VERIFIER_CB_ENABLED=1`), additional Prometheus
series are emitted per provider:

- `guardrail_verifier_circuit_open_total{provider}` — calls skipped because the
  circuit breaker was open.
- `guardrail_verifier_provider_error_total{provider}` — provider exceptions (excluding
  timeouts).
- `guardrail_verifier_circuit_state{provider}` — gauge of breaker state (1=open,
  0=closed, emitted only if gauges are supported).

## Security (optional)

| Name                   | Type   | Default | Allowed Range | Examples                 | Notes                                      |
|------------------------|--------|---------|---------------|--------------------------|--------------------------------------------|
| `API_SECURITY_ENABLED` | bool   | `false` | —             | `1`, `true`, `yes`       | When enabled, attaches auth + rate limiting |
| `GUARDRAIL_API_KEYS`   | csv    | —       | —             | `abc123,def456`          | Comma/colon/semicolon-separated API keys   |
| `SECURED_PATH_PREFIXES`| csv    | `/v1`   | —             | `/v1,/admin`             | Path prefixes guarded by security middlews |
| `RATE_LIMIT_RPS`       | float  | `0.0`   | `>= 0`        | `2.5`                    | 0 disables rate limiting                    |
| `RATE_LIMIT_BURST`     | int    | `0`     | `>= 0`        | `10`                     | Bucket capacity for bursts                  |

## CORS (optional)

| Name                  | Type  | Default            | Allowed Range | Examples                               | Notes                                 |
|-----------------------|-------|--------------------|---------------|----------------------------------------|---------------------------------------|
| `CORS_ENABLED`        | bool  | `false`            | —             | `1`, `true`                            | Enable CORS middleware                |
| `CORS_ALLOW_ORIGINS`  | csv   | _(required if on)_ | —             | `https://app.example.com,https://x.io` | Origins allowed; **no wildcard by default** |
| `CORS_ALLOW_METHODS`  | csv   | `GET,POST,OPTIONS` | —             | `GET,POST,PUT,DELETE,OPTIONS`          | HTTP methods                          |
| `CORS_ALLOW_HEADERS`  | csv   | `*`                | —             | `Authorization,Content-Type`           | Request headers                       |
| `CORS_ALLOW_CREDENTIALS` | bool | `false`          | —             | `1`, `true`                            | Access-Control-Allow-Credentials      |
| `CORS_MAX_AGE`        | int   | `600`              | `>=0`         | `86400`                                | Preflight cache max-age (seconds)     |

## Security Headers (optional)

| Name                               | Type  | Default                         | Notes                                      |
|------------------------------------|-------|---------------------------------|--------------------------------------------|
| `SEC_HEADERS_ENABLED`              | bool  | `false`                         | Enable security headers middleware         |
| `SEC_HEADERS_FRAME_DENY`           | bool  | `true`                          | `X-Frame-Options: DENY`                    |
| `SEC_HEADERS_CONTENT_TYPE_NOSNIFF` | bool  | `true`                          | `X-Content-Type-Options: nosniff`          |
| `SEC_HEADERS_REFERRER_POLICY`      | str   | `no-referrer`                   | `Referrer-Policy` value                    |
| `SEC_HEADERS_PERMISSIONS_POLICY`   | str   | `geolocation=()`                | `Permissions-Policy` directives            |
| `SEC_HEADERS_HSTS`                 | bool  | `false`                         | Add HSTS header (enable only behind HTTPS) |
| `SEC_HEADERS_HSTS_VALUE`           | str   | `max-age=31536000; includeSubDomains` | HSTS value                      |

## Request Size Limits

| Name               | Type | Default | Range | Example |
|--------------------|------|---------|-------|---------|
| MAX_REQUEST_BYTES  | int  | 0       | ≥ 0   | 1048576 |

Notes:
- `0` disables the limiter.
- If `Content-Length` exceeds the limit, the request is rejected with HTTP 413.

## JSON Logging (optional)

| Name                    | Type  | Default | Notes                                                                 |
|-------------------------|-------|---------|-----------------------------------------------------------------------|
| `LOG_JSON_ENABLED`      | bool  | `false` | Enable JSON logs (both snapshot and per-request, unless overridden).  |
| `LOG_SNAPSHOT_ENABLED`  | bool  | `—`     | Defaults to `LOG_JSON_ENABLED`. Emit a single startup config snapshot.|
| `LOG_REQUESTS_ENABLED`  | bool  | `—`     | Defaults to `LOG_JSON_ENABLED`. Per-request access logs.              |
| `LOG_REQUESTS_PATHS`    | csv   | `/`     | Path prefixes to log (e.g., `/v1,/admin`).                            |
| `LOG_MIN_STATUS`        | int   | `0`     | Only log responses with status >= this value.                         |

## Circuit Breaker (optional)

| Name                               | Type | Default | Allowed Range | Notes                                                |
|------------------------------------|------|---------|---------------|------------------------------------------------------|
| `VERIFIER_CB_ENABLED`              | bool | `false` | —             | Enable circuit breaker support for external calls.   |
| `VERIFIER_CB_FAILURE_THRESHOLD`    | int  | `5`     | `>= 1`        | Failures before opening the breaker.                 |
| `VERIFIER_CB_RECOVERY_SECONDS`     | int  | `30`    | `>= 1`        | Cooldown before trying half-open probes.             |
| `VERIFIER_CB_HALF_OPEN_MAX_CALLS`  | int  | `1`     | `>= 1`        | Trial calls allowed in half-open before blocking.    |

## Health / Probes

| Name                   | Type | Default | Range     | Example | Notes                                  |
|------------------------|------|---------|-----------|---------|----------------------------------------|
| HEALTH_READY_DELAY_MS  | int  | 0       | ≥ 0 ms    | 1500    | Delay before `/ready` returns 200.     |

Endpoints:
- `GET /live`  → always returns 200 with `{"status":"ok","ok":true}`
- `GET /ready` → returns 503 during startup delay, then 200 with same payload as `/live`.

## Version & Build Info

| Endpoint  | Description                                    |
|-----------|------------------------------------------------|
| `/version`| Returns build metadata and a sanitized config snapshot.

**Payload**
```json
{
  "info": {
    "version": "<APP_VERSION>",
    "commit": "<GIT_SHA>",
    "build_time": "<BUILD_TIME>",
    "python": "3.11.x",
    "platform": "...",
    "fastapi": "...",
    "starlette": "..."
  },
  "config": {
    "verifier_sampling_pct": 0.0..1.0,
    "verifier_latency_budget_ms": null | int,
    "circuit_breaker_enabled": true|false,
    "rate_limit_rps": int,
    "rate_limit_burst": int,
    "cors_enabled": true|false,
    "api_security_enabled": true|false
  }
}
```

Environment variables used (optional)

APP_VERSION – arbitrary app version string

GIT_SHA – git commit sha

BUILD_TIME – build timestamp (ISO-8601 recommended)


## Web Crawlers & Security.txt

| Name                      | Type | Default | Example                            | Notes                                  |
|---------------------------|------|---------|------------------------------------|----------------------------------------|
| ROBOTS_ALLOW              | str  | —       | `/public,/health`                  | Comma-separated paths to allow.        |
| ROBOTS_DISALLOW           | str  | `/admin`| `/private`                         | Comma-separated paths to disallow.     |
| SECURITY_CONTACT          | str  | —       | `mailto:security@example.com`      | Enables `/.well-known/security.txt`.   |
| SECURITY_POLICY           | str  | —       | `https://example.com/security`     | Optional link to policy.               |
| SECURITY_ENCRYPTION       | str  | —       | `https://example.com/pgp.txt`      | Optional PGP key or location.          |
| SECURITY_ACKNOWLEDGEMENTS | str  | —       | `https://example.com/hall-of-fame` | Optional acknowledgements page.        |
| SECURITY_PREFERRED_LANG   | str  | —       | `en, fr`                           | Optional list of preferred languages.  |

**Endpoints**
- `GET /robots.txt` — text/plain. Defaults to disallow `/admin`.
- `GET /.well-known/security.txt` — text/plain. Returned only if `SECURITY_CONTACT` is set.

## Runbook

## Graceful Shutdown / Probes

| Name                  | Type | Default | Range | Example | Notes                                    |
|-----------------------|------|---------|-------|---------|------------------------------------------|
| HEALTH_READY_DELAY_MS | int  | 0       | ≥ 0   | 1500    | Delay before `/ready` returns 200.       |
| HEALTH_DRAIN_DELAY_MS | int  | 0       | ≥ 0   | 2000    | Extra delay during shutdown after `/ready` flips to 503. |

Behavior:
- `GET /live`  → always `200 {"status":"ok","ok":true}`
- `GET /ready` → `503` until startup delay elapses; `503` again during shutdown/drain.

## Readiness Probes (Verifier prerequisites)

| Name                       | Type | Default    | Range | Example                       | Notes                                                    |
|----------------------------|------|------------|-------|-------------------------------|----------------------------------------------------------|
| PROBE_VERIFIER_ENABLED     | bool | false      | —     | true                          | If true, `/ready` also requires probe to pass.           |
| PROBE_VERIFIER_REQUIRED_ENVS | str | OPENAI_API_KEY | —   | OPENAI_API_KEY,OTHER_TOKEN    | Comma-separated envs that must be non-empty.             |
| PROBE_VERIFIER_INTERVAL_MS | int  | 30000      | ≥ 0   | 10000                         | Periodic re-check; 0 = only at startup.                  |

Behavior:
- If disabled, `/ready` behaves exactly as before (delay/drain only).
- If enabled, `/ready` is 503 until all required env vars are present.

## Response Compression

| Name                       | Type | Default | Range | Example |
|----------------------------|------|---------|-------|---------|
| COMPRESSION_ENABLED        | bool | false   | —     | true    |
| COMPRESSION_MIN_SIZE_BYTES | int  | 500     | ≥ 0   | 128     |

Notes:
- When enabled and the client sends `Accept-Encoding: gzip`, responses larger than
  `COMPRESSION_MIN_SIZE_BYTES` are gzipped.

## Metrics Endpoint

| Name                 | Type | Default | Example | Notes                                              |
|----------------------|------|---------|---------|----------------------------------------------------|
| METRICS_ROUTE_ENABLED| bool | false   | true    | Enables `GET /metrics` (Prometheus exposition).    |
| METRICS_API_KEY      | str  | —       | secret  | If set, requires `X-API-KEY` or `Bearer` token.    |

- Content type: `text/plain; version=0.0.4; charset=utf-8`
- The route is hidden (404) unless both enabled **and** `prometheus_client` is installed.

