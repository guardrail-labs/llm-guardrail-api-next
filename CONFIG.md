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
