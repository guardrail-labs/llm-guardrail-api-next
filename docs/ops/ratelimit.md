# Redis Rate Limit Backend

## NOSCRIPT Auto-Reload

When Redis evicts the rate-limit Lua script (for example after a failover or a manual `SCRIPT FLUSH`), the Guardrail Redis backend now automatically reloads the script and retries the command once. If the reload and retry succeed we increment the Prometheus counter `guardrail_ratelimit_redis_script_reload_total`. When either the reload fails or the retry errors, the rate limiter falls back to the hard-error path (deny/report) just like any other Redis failure.
