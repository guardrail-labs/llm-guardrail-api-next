# Runbook: Readiness Failing

1. Inspect `guardrail_readyz_ok`, `guardrail_readyz_redis_ok`.
2. If Redis consumer down, check logs for NOSCRIPT fallback or connection errors.
3. Bounce the affected worker; if persistent, fail over to secondary Redis (if configured).

(Short, focused; expand later.)
