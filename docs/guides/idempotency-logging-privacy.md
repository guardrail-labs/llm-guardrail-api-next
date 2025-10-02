# Idempotency logging privacy

- The system **never logs full X-Idempotency-Key**; only a masked prefix with an ellipsis
  and short hash suffix is emitted.
- To include potentially sensitive fields (e.g., request headers) in idempotency logs
  for short-term debugging, set:

```bash
export IDEMP_LOG_INCLUDE_PII=1   # defaults to 0 (disabled)
```

Every idempotency event includes privacy_mode: pii_enabled|pii_disabled and
mask_prefix_len, making posture auditable via log queries.

Tip (Loki/ELK): filter by privacy_mode to locate the time windows when PII logging
was enabled and review change-control tickets accordingly.
