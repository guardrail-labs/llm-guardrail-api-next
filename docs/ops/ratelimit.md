# Redis rate-limit backend

On NOSCRIPT, the backend `SCRIPT LOAD`s the Lua, retries once, and increments `guardrail_ratelimit_redis_script_reload_total` on success. Failures follow the hard-error path.
