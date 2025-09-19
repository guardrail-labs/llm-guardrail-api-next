# Redis rate-limit backend

On NOSCRIPT, the backend `SCRIPT LOAD`s the Lua, retries once, and increments `guardrail_ratelimit_redis_script_reload_total` on success. If the reload or retry still fails, it performs a one-time direct `EVAL` fallback to keep the limiter accurate; only a successful reload+retry increments the metric. The async Redis rate-limit backend mirrors this flow so that both implementations recover and emit metrics identically.
