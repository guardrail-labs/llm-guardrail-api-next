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

## Security (optional)

| Name                   | Type   | Default | Allowed Range | Examples                 | Notes                                      |
|------------------------|--------|---------|---------------|--------------------------|--------------------------------------------|
| `API_SECURITY_ENABLED` | bool   | `false` | —             | `1`, `true`, `yes`       | When enabled, attaches auth + rate limiting |
| `GUARDRAIL_API_KEYS`   | csv    | —       | —             | `abc123,def456`          | Comma/colon/semicolon-separated API keys   |
| `SECURED_PATH_PREFIXES`| csv    | `/v1`   | —             | `/v1,/admin`             | Path prefixes guarded by security middlews |
| `RATE_LIMIT_RPS`       | float  | `0.0`   | `>= 0`        | `2.5`                    | 0 disables rate limiting                    |
| `RATE_LIMIT_BURST`     | int    | `0`     | `>= 0`        | `10`                     | Bucket capacity for bursts                  |
