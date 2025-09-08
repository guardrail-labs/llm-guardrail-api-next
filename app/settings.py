"""Settings constants for verifier limits.

This lightweight module provides default values referenced by the verifier
service. Real deployments may populate these from environment or a config
system.
"""

import os

VERIFIER_MAX_TOKENS_PER_REQUEST = 4000
VERIFIER_DAILY_TOKEN_BUDGET = 100000
VERIFIER_CIRCUIT_FAILS = 5
VERIFIER_CIRCUIT_WINDOW_S = 60
VERIFIER_CIRCUIT_COOLDOWN_S = 30
VERIFIER_TIMEOUT_MS = 8000

# Provider pipeline configuration
VERIFIER_PROVIDERS = (
    os.getenv("VERIFIER_PROVIDERS", "local_rules").strip() or "local_rules"
)
# Per-provider call timebox (ms)
VERIFIER_PROVIDER_TIMEOUT_MS = int(
    os.getenv("VERIFIER_PROVIDER_TIMEOUT_MS", "1600") or "1600"
)

# Anthropic provider (optional)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
VERIFIER_ANTHROPIC_MODEL = os.getenv(
    "VERIFIER_ANTHROPIC_MODEL", "claude-3-haiku"
).strip()

# --- Verifier harm-cache persistence (optional Redis) ---
VERIFIER_HARM_CACHE_URL = os.getenv("VERIFIER_HARM_CACHE_URL", "").strip()
# Days to keep a harmful fingerprint in the cache (default 90 days)
VERIFIER_HARM_TTL_DAYS = int(os.getenv("VERIFIER_HARM_TTL_DAYS", "90") or "90")

# Hidden-text scanning (opt-in)
HIDDEN_TEXT_SCAN = (os.getenv("HIDDEN_TEXT_SCAN", "0").strip() == "1")
# Soft size cap for scans (bytes); 0 disables cap
HIDDEN_TEXT_SCAN_MAX_BYTES = int(
    os.getenv("HIDDEN_TEXT_SCAN_MAX_BYTES", "1048576") or "0"
)

