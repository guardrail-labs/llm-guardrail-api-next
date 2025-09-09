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

# Per-provider breaker config
VERIFIER_PROVIDER_BREAKER_FAILS = int(
    os.getenv("VERIFIER_PROVIDER_BREAKER_FAILS", "5") or "5"
)
VERIFIER_PROVIDER_BREAKER_WINDOW_S = int(
    os.getenv("VERIFIER_PROVIDER_BREAKER_WINDOW_S", "60") or "60"
)
VERIFIER_PROVIDER_BREAKER_COOLDOWN_S = int(
    os.getenv("VERIFIER_PROVIDER_BREAKER_COOLDOWN_S", "30") or "30"
)

# Quota-aware skip (opt-in; on by default)
VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED = (
    os.getenv("VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED", "1").strip() == "1"
)

# Default skip window if no explicit reset is provided by the provider (seconds).
VERIFIER_PROVIDER_QUOTA_DEFAULT_SKIP_S = int(
    os.getenv("VERIFIER_PROVIDER_QUOTA_DEFAULT_SKIP_S", "60") or "60"
)

# Maximum cap for provider-advertised retry-after to avoid pathological values.
VERIFIER_PROVIDER_QUOTA_MAX_SKIP_S = int(
    os.getenv("VERIFIER_PROVIDER_QUOTA_MAX_SKIP_S", "600") or "600"
)

# Result cache for verify_intent (opt-in; defaults to on)
VERIFIER_RESULT_CACHE_ENABLED = (
    os.getenv("VERIFIER_RESULT_CACHE_ENABLED", "1").strip() == "1"
)

# Optional Redis for cross-process cache. If empty, in-memory only.
VERIFIER_RESULT_CACHE_URL = os.getenv("VERIFIER_RESULT_CACHE_URL", "").strip()

# TTL in seconds for cache entries (both safe and unsafe)
VERIFIER_RESULT_CACHE_TTL_SECONDS = int(
    os.getenv("VERIFIER_RESULT_CACHE_TTL_SECONDS", "86400") or "0"
)

# Reuse ingress verification for matching egress requests (opt-in; on by default)
VERIFIER_EGRESS_REUSE_ENABLED = (
    os.getenv("VERIFIER_EGRESS_REUSE_ENABLED", "1").strip() == "1"
)

# TTL for reuse entries (short-lived, per-request)
VERIFIER_EGRESS_REUSE_TTL_SECONDS = int(
    os.getenv("VERIFIER_EGRESS_REUSE_TTL_SECONDS", "300") or "300"
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

# Enable policy hook: when 1 and a rule matches, set decision to clarify/deny.
HIDDEN_TEXT_POLICY = (os.getenv("HIDDEN_TEXT_POLICY", "0").strip() == "1")

# Comma-separated reason lists -> action. Reasons are normalized lowercase tokens
# you already emit (e.g., style_hidden, attr_hidden, zero_width_chars, docx_vanish).
HIDDEN_TEXT_DENY_REASONS = os.getenv("HIDDEN_TEXT_DENY_REASONS", "docx_vanish").strip()
HIDDEN_TEXT_CLARIFY_REASONS = os.getenv(
    "HIDDEN_TEXT_CLARIFY_REASONS",
    "style_hidden,attr_hidden,zero_width_chars,docx_track_ins,docx_track_del,docx_comments",
).strip()

# Optional format allowlist (comma-separated): html, docx, pdf, etc. Empty => all
HIDDEN_TEXT_FORMATS = os.getenv("HIDDEN_TEXT_FORMATS", "").strip()

# Optional minimum reasons required to trigger (default 1)
HIDDEN_TEXT_MIN_MATCH = int(os.getenv("HIDDEN_TEXT_MIN_MATCH", "1") or "1")

