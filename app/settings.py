"""Settings constants for verifier limits.

This lightweight module provides default values referenced by the verifier
service. Real deployments may populate these from environment or a config
system.
"""
from __future__ import annotations

import os
from typing import List, Literal, Set

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

IdemMode = Literal["off", "observe", "enforce"]


class IdempotencySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    mode: IdemMode = Field(
        "observe",
        validation_alias=AliasChoices("IDEMPOTENCY_MODE"),
    )
    enforce_methods: Set[str] = Field(
        default_factory=lambda: {"POST", "PUT", "PATCH"},
        validation_alias=AliasChoices("IDEMPOTENCY_ENFORCE_METHODS"),
    )
    exclude_paths: List[str] = Field(
        default_factory=lambda: ["/health", "/metrics", "/admin/*"],
        validation_alias=AliasChoices("IDEMPOTENCY_EXCLUDE_PATHS"),
    )
    lock_ttl_s: int = Field(
        60, ge=1, le=600, validation_alias=AliasChoices("IDEMPOTENCY_LOCK_TTL_S")
    )
    wait_budget_ms: int = Field(
        2000, ge=0, le=30000, validation_alias=AliasChoices("IDEMPOTENCY_WAIT_BUDGET_MS")
    )
    jitter_ms: int = Field(
        50, ge=0, le=1000, validation_alias=AliasChoices("IDEMPOTENCY_JITTER_MS")
    )
    replay_window_s: int = Field(
        300, ge=1, le=86400, validation_alias=AliasChoices("IDEMPOTENCY_REPLAY_WINDOW_S")
    )
    strict_fail_closed: bool = Field(
        False, validation_alias=AliasChoices("IDEMPOTENCY_STRICT_FAIL_CLOSED")
    )
    mask_prefix_len: int = Field(
        8, ge=4, le=16, validation_alias=AliasChoices("IDEMPOTENCY_MASK_PREFIX_LEN")
    )
    shadow_sample_rate: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices("IDEMPOTENCY_SHADOW_SAMPLE_RATE"),
    )
    store_backend: Literal["memory", "redis"] = Field(
        "memory", validation_alias=AliasChoices("IDEMPOTENCY_STORE_BACKEND")
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    env: Literal["dev", "stage", "prod", "test"] = Field(
        "dev", validation_alias=AliasChoices("APP_ENV")
    )
    # Use a concrete default instance (avoids mypy issues with default_factory)
    idempotency: IdempotencySettings = IdempotencySettings()

    def effective(self) -> "Settings":
        """Apply safe-by-default overrides per environment."""
        eff = self.model_copy(deep=True)
        if self.env == "dev":
            eff.idempotency.mode = (
                "observe"
                if self.idempotency.mode == "observe"
                else self.idempotency.mode
            )
            eff.idempotency.lock_ttl_s = min(self.idempotency.lock_ttl_s, 30)
            eff.idempotency.strict_fail_closed = False
        elif self.env == "stage":
            eff.idempotency.mode = (
                "observe"
                if self.idempotency.mode == "observe"
                else self.idempotency.mode
            )
            eff.idempotency.lock_ttl_s = max(self.idempotency.lock_ttl_s, 60)
            eff.idempotency.strict_fail_closed = False
        elif self.env == "prod":
            eff.idempotency.mode = (
                "enforce"
                if self.idempotency.mode in {"observe", "enforce"}
                else self.idempotency.mode
            )
            eff.idempotency.lock_ttl_s = max(self.idempotency.lock_ttl_s, 120)
        return eff


def get_settings(env: str | None = None) -> Settings:
    """Helper for tests and callers that want explicit env (mypy-friendly)."""
    if env is not None:
        return Settings(env=env).effective()
    return Settings().effective()


# Module-level settings (use APP_ENV or default dev)
settings = get_settings(env=None)

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

# Adaptive provider routing (opt-in; defaults to on)
VERIFIER_ADAPTIVE_ROUTING_ENABLED = (
    os.getenv("VERIFIER_ADAPTIVE_ROUTING_ENABLED", "1").strip() == "1"
)

# EWMA half-life for latency/success weighting (seconds)
VERIFIER_ADAPTIVE_HALFLIFE_S = int(
    os.getenv("VERIFIER_ADAPTIVE_HALFLIFE_S", "120") or "120"
)

# Minimum samples before reordering (avoid thrash)
VERIFIER_ADAPTIVE_MIN_SAMPLES = int(
    os.getenv("VERIFIER_ADAPTIVE_MIN_SAMPLES", "5") or "5"
)

# Score penalties (ms-equivalent) for issues
VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS = int(
    os.getenv("VERIFIER_ADAPTIVE_PENALTY_TIMEOUT_MS", "800") or "800"
)
VERIFIER_ADAPTIVE_PENALTY_ERROR_MS = int(
    os.getenv("VERIFIER_ADAPTIVE_PENALTY_ERROR_MS", "400") or "400"
)
VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS = int(
    os.getenv("VERIFIER_ADAPTIVE_PENALTY_RATE_LIMIT_MS", "600") or "600"
)

# Sticky ordering window before we allow re-rank (seconds)
VERIFIER_ADAPTIVE_STICKY_S = int(os.getenv("VERIFIER_ADAPTIVE_STICKY_S", "30") or "30")

# Cap how often we'll keep per-tenant/bot stats in memory (seconds)
VERIFIER_ADAPTIVE_TTL_S = int(os.getenv("VERIFIER_ADAPTIVE_TTL_S", "900") or "900")

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

# Shadow-call alternate providers without changing decisions
VERIFIER_SANDBOX_ENABLED = os.getenv("VERIFIER_SANDBOX_ENABLED", "1").strip() == "1"
VERIFIER_SANDBOX_SAMPLE_RATE = float(
    os.getenv("VERIFIER_SANDBOX_SAMPLE_RATE", "0.05") or "0.05"
)
VERIFIER_SANDBOX_TIMEOUT_MS = int(os.getenv("VERIFIER_SANDBOX_TIMEOUT_MS", "500") or "500")
VERIFIER_SANDBOX_MAX_CONCURRENCY = int(
    os.getenv("VERIFIER_SANDBOX_MAX_CONCURRENCY", "2") or "2"
)
VERIFIER_SANDBOX_SYNC_FOR_TESTS = (
    os.getenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "0").strip() == "1"
)
VERIFIER_SANDBOX_MAX_RESULTS = int(
    os.getenv("VERIFIER_SANDBOX_MAX_RESULTS", "3") or "3"
)

VERIFIER_SANDBOX_DIFF_ENABLED = (
    os.getenv("VERIFIER_SANDBOX_DIFF_ENABLED", "1").strip() == "1"
)
VERIFIER_SANDBOX_DIFF_ATTACH_HEADER = (
    os.getenv("VERIFIER_SANDBOX_DIFF_ATTACH_HEADER", "0").strip() == "1"
)
VERIFIER_SANDBOX_DIFF_MAX_ATTACH = int(
    os.getenv("VERIFIER_SANDBOX_DIFF_MAX_ATTACH", "2") or "2"
)
VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE = (
    os.getenv("VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE", "1").strip() == "1"
)
VERIFIER_SANDBOX_DIFF_AUDIT_RATE = float(
    os.getenv("VERIFIER_SANDBOX_DIFF_AUDIT_RATE", "0.0") or "0.0"
)

# Anthropic provider (optional)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
VERIFIER_ANTHROPIC_MODEL = os.getenv("VERIFIER_ANTHROPIC_MODEL", "claude-3-haiku").strip()

# --- Verifier harm-cache persistence (optional Redis) ---
VERIFIER_HARM_CACHE_URL = os.getenv("VERIFIER_HARM_CACHE_URL", "").strip()
VERIFIER_HARM_TTL_DAYS = int(os.getenv("VERIFIER_HARM_TTL_DAYS", "90") or "90")

# Hidden-text scanning (opt-in)
HIDDEN_TEXT_SCAN = os.getenv("HIDDEN_TEXT_SCAN", "0").strip() == "1"
HIDDEN_TEXT_SCAN_MAX_BYTES = int(
    os.getenv("HIDDEN_TEXT_SCAN_MAX_BYTES", "1048576") or "0"
)
HIDDEN_TEXT_POLICY = os.getenv("HIDDEN_TEXT_POLICY", "0").strip() == "1"
HIDDEN_TEXT_DENY_REASONS = os.getenv(
    "HIDDEN_TEXT_DENY_REASONS", "docx_vanish"
).strip()
HIDDEN_TEXT_CLARIFY_REASONS = os.getenv(
    "HIDDEN_TEXT_CLARIFY_REASONS",
    "style_hidden,attr_hidden,zero_width_chars,docx_track_ins,docx_track_del,docx_comments",
).strip()
HIDDEN_TEXT_FORMATS = os.getenv("HIDDEN_TEXT_FORMATS", "").strip()
HIDDEN_TEXT_MIN_MATCH = int(os.getenv("HIDDEN_TEXT_MIN_MATCH", "1") or "1")

# Cap bytes for egress inspection peek (0 disables)
EGRESS_INSPECT_MAX_BYTES = int(os.getenv("EGRESS_INSPECT_MAX_BYTES", "4096") or "4096")

IDEMP_ENABLED = os.getenv("IDEMP_ENABLED", "true").lower() == "true"
IDEMP_METHODS = tuple(sorted(settings.idempotency.enforce_methods))
IDEMP_TTL_SECONDS = settings.idempotency.lock_ttl_s
IDEMP_MAX_BODY_BYTES = int(os.getenv("IDEMP_MAX_BODY_BYTES", "1048576"))  # 1 MiB
IDEMP_CACHE_STREAMING = os.getenv("IDEMP_CACHE_STREAMING", "false").lower() == "true"
IDEMP_TOUCH_ON_REPLAY = os.getenv("IDEMP_TOUCH_ON_REPLAY", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
IDEMP_REDIS_URL = os.getenv("IDEMP_REDIS_URL", "redis://localhost:6379/0")
IDEMP_REDIS_NAMESPACE = os.getenv("IDEMP_REDIS_NAMESPACE", "idem")
IDEMP_RECENT_ZSET_MAX = int(os.getenv("IDEMP_RECENT_ZSET_MAX", "5000") or "5000")
