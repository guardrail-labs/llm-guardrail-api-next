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

# --- Verifier harm-cache persistence (optional Redis) ---
VERIFIER_HARM_CACHE_URL = os.getenv("VERIFIER_HARM_CACHE_URL", "").strip()
# Days to keep a harmful fingerprint in the cache (default 90 days)
VERIFIER_HARM_TTL_DAYS = int(os.getenv("VERIFIER_HARM_TTL_DAYS", "90") or "90")

