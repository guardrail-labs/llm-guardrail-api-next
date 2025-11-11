"""Settings constants for verifier limits.

This lightweight module provides default values referenced by the verifier
service. Real deployments may populate these from environment or a config
system.
"""

import base64
import json
import os
from typing import TYPE_CHECKING, Any, List, Literal, Set, cast, overload

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources.base import PydanticBaseSettingsSource
from pydantic_settings.sources.providers.env import EnvSettingsSource

# Streaming defaults
STREAM_HEARTBEAT_SEC: float = 15.0
STREAM_MAX_IDLE_SEC: float = 120.0
STREAM_MAX_HOLD_BYTES: int = 4096
# Paths that may be excluded from SSE header meddling (if you later add gzip by path)
STREAM_SSE_EXCLUDE_PATHS: tuple[str, ...] = ("/admin",)

# Unicode normalization defaults for ingress guard
CONFUSABLES_MODE: str = os.getenv("CONFUSABLES_MODE", "pass").strip() or "pass"
CONFUSABLES_FORM: str = os.getenv("CONFUSABLES_FORM", "NFKC").strip() or "NFKC"
CONFUSABLES_MAX_BODY_BYTES: int = int(os.getenv("CONFUSABLES_MAX_BODY_BYTES", "131072") or "131072")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    text = raw.strip().lower()
    if text in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


UNICODE_SANITIZER_ENABLED: bool = _env_bool("UNICODE_SANITIZER_ENABLED", True)
SANITIZER_CONFUSABLES_ENABLED: bool = _env_bool("SANITIZER_CONFUSABLES_ENABLED", False)
UNICODE_BLOCK_ON_BIDI: bool = _env_bool("UNICODE_BLOCK_ON_BIDI", True)
UNICODE_BLOCK_ON_MIXED_SCRIPT: bool = _env_bool("UNICODE_BLOCK_ON_MIXED_SCRIPT", True)
UNICODE_EMOJI_RATIO_WARN: float = float(os.getenv("UNICODE_EMOJI_RATIO_WARN", "0.5") or "0.5")

# Guardrail arm coordination defaults
ARM_INGRESS_ENABLED: bool = _env_bool("ARM_INGRESS_ENABLED", True)
ARM_EGRESS_ENABLED: bool = _env_bool("ARM_EGRESS_ENABLED", True)
EGRESS_ONLY_ON_INGRESS_DEGRADED: bool = _env_bool(
    "EGRESS_ONLY_ON_INGRESS_DEGRADED", True
)
INGRESS_DEGRADED_LAG_MS: int = int(os.getenv("INGRESS_DEGRADED_LAG_MS", "2000") or "2000")

HTTPX_MAX_CONNECTIONS: int = 200
HTTPX_MAX_KEEPALIVE: int = 100
HTTPX_KEEPALIVE_S: int = 20
HTTPX_TIMEOUT_S: int = 30

IdemMode = Literal["off", "observe", "enforce"]

_DEFAULT_IDEMPOTENCY_MODE: IdemMode = "observe"
_DEFAULT_IDEMPOTENCY_METHODS = ("POST", "PUT", "PATCH")
_DEFAULT_IDEMPOTENCY_EXCLUDE_PATHS = ("/health", "/metrics", "/admin/*")
_DEFAULT_IDEMPOTENCY_LOCK_TTL = 60
_DEFAULT_IDEMPOTENCY_WAIT_BUDGET_MS = 2000
_DEFAULT_IDEMPOTENCY_JITTER_MS = 50
_DEFAULT_IDEMPOTENCY_REPLAY_WINDOW_S = 300
_DEFAULT_IDEMPOTENCY_MASK_PREFIX_LEN = 8
_DEFAULT_IDEMPOTENCY_SHADOW_SAMPLE_RATE = 1.0
_DEFAULT_IDEMPOTENCY_STORE_BACKEND: Literal["memory", "redis"] = "memory"


def _csv_to_list(value: str) -> List[str]:
    items = [part.strip() for part in value.split(",")]
    return [item for item in items if item]


def _json_or_csv_to_list(value: str) -> List[str]:
    text = value.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return _csv_to_list(text)
        if isinstance(decoded, str):
            return _csv_to_list(decoded)
        if isinstance(decoded, (list, tuple, set)):
            result: List[str] = []
            for item in decoded:
                piece = str(item).strip()
                if piece:
                    result.append(piece)
            return result
        return []
    return _csv_to_list(text)


class _CsvFriendlyEnvSettingsSource(EnvSettingsSource):
    def decode_complex_value(self, field_name: str, field: Any, value: Any) -> Any:
        try:
            return super().decode_complex_value(field_name, field, value)
        except ValueError:
            return value


class IdempotencySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        if isinstance(env_settings, EnvSettingsSource):
            env_settings = _CsvFriendlyEnvSettingsSource(
                settings_cls,
                case_sensitive=env_settings.case_sensitive,
                env_prefix=env_settings.env_prefix,
                env_nested_delimiter=env_settings.env_nested_delimiter,
                env_nested_max_split=env_settings.env_nested_max_split,
                env_ignore_empty=env_settings.env_ignore_empty,
                env_parse_none_str=env_settings.env_parse_none_str,
                env_parse_enums=env_settings.env_parse_enums,
            )
        return init_settings, env_settings, dotenv_settings, file_secret_settings

    mode: IdemMode = Field(
        _DEFAULT_IDEMPOTENCY_MODE,
        validation_alias=AliasChoices("IDEMPOTENCY_MODE"),
    )
    enforce_methods: Set[str] = Field(
        default_factory=lambda: set(_DEFAULT_IDEMPOTENCY_METHODS),
        validation_alias=AliasChoices("IDEMPOTENCY_ENFORCE_METHODS"),
    )
    exclude_paths: List[str] = Field(
        default_factory=lambda: list(_DEFAULT_IDEMPOTENCY_EXCLUDE_PATHS),
        validation_alias=AliasChoices("IDEMPOTENCY_EXCLUDE_PATHS"),
    )
    lock_ttl_s: int = Field(
        _DEFAULT_IDEMPOTENCY_LOCK_TTL,
        ge=1,
        le=600,
        validation_alias=AliasChoices("IDEMPOTENCY_LOCK_TTL_S"),
    )
    wait_budget_ms: int = Field(
        _DEFAULT_IDEMPOTENCY_WAIT_BUDGET_MS,
        ge=0,
        le=30000,
        validation_alias=AliasChoices("IDEMPOTENCY_WAIT_BUDGET_MS"),
    )
    jitter_ms: int = Field(
        _DEFAULT_IDEMPOTENCY_JITTER_MS,
        ge=0,
        le=1000,
        validation_alias=AliasChoices("IDEMPOTENCY_JITTER_MS"),
    )
    replay_window_s: int = Field(
        _DEFAULT_IDEMPOTENCY_REPLAY_WINDOW_S,
        ge=1,
        le=86400,
        validation_alias=AliasChoices("IDEMPOTENCY_REPLAY_WINDOW_S"),
    )
    strict_fail_closed: bool = Field(
        False,
        validation_alias=AliasChoices("IDEMPOTENCY_STRICT_FAIL_CLOSED"),
    )
    mask_prefix_len: int = Field(
        _DEFAULT_IDEMPOTENCY_MASK_PREFIX_LEN,
        ge=4,
        le=16,
        validation_alias=AliasChoices("IDEMPOTENCY_MASK_PREFIX_LEN"),
    )
    shadow_sample_rate: float = Field(
        _DEFAULT_IDEMPOTENCY_SHADOW_SAMPLE_RATE,
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices("IDEMPOTENCY_SHADOW_SAMPLE_RATE"),
    )
    store_backend: Literal["memory", "redis"] = Field(
        _DEFAULT_IDEMPOTENCY_STORE_BACKEND,
        validation_alias=AliasChoices("IDEMPOTENCY_STORE_BACKEND"),
    )

    @field_validator("enforce_methods", mode="before")
    @classmethod
    def _parse_methods_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return {item.upper() for item in _json_or_csv_to_list(value)}
        if isinstance(value, (list, set, tuple)):
            return {str(item).strip().upper() for item in value if str(item).strip()}
        return value

    @field_validator("exclude_paths", mode="before")
    @classmethod
    def _parse_paths_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return _json_or_csv_to_list(value)
        if isinstance(value, (list, set, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        return value


if TYPE_CHECKING:

    def _load_idempotency_from_env() -> IdempotencySettings: ...
else:

    def _load_idempotency_from_env() -> IdempotencySettings:
        return IdempotencySettings()


def _default_idempotency_settings() -> IdempotencySettings:
    loaded = _load_idempotency_from_env()
    data = loaded.model_dump()
    return IdempotencySettings.model_construct(**data)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    env: Literal["dev", "stage", "prod", "test"] = Field(
        "dev",
        validation_alias=AliasChoices("APP_ENV"),
    )
    idempotency: IdempotencySettings = Field(
        default_factory=_default_idempotency_settings,
    )

    def effective(self) -> "Settings":
        eff = self.model_copy(deep=True)
        if eff.env == "dev":
            if eff.idempotency.mode == "observe":
                eff.idempotency.mode = "observe"
            eff.idempotency.lock_ttl_s = min(eff.idempotency.lock_ttl_s, 30)
            eff.idempotency.strict_fail_closed = False
        elif eff.env == "stage":
            if eff.idempotency.mode == "observe":
                eff.idempotency.mode = "observe"
            eff.idempotency.lock_ttl_s = max(eff.idempotency.lock_ttl_s, 60)
            eff.idempotency.strict_fail_closed = False
        elif eff.env == "prod":
            eff.idempotency.mode = (
                "enforce"
                if eff.idempotency.mode in {"observe", "enforce"}
                else eff.idempotency.mode
            )
            eff.idempotency.lock_ttl_s = max(eff.idempotency.lock_ttl_s, 120)
        return eff


if TYPE_CHECKING:

    def _load_settings(**data: Any) -> Settings: ...
else:

    def _load_settings(**data: Any) -> Settings:
        return Settings(**data)


@overload
def get_settings(env: Literal["dev", "stage", "prod", "test"]) -> Settings: ...


@overload
def get_settings(env: None = ...) -> Settings: ...


def get_settings(env: str | None = None) -> Settings:
    if env is not None:
        lit = cast(Literal["dev", "stage", "prod", "test"], env)
        return _load_settings(env=lit).effective()
    return _load_settings().effective()


settings = get_settings(None)


VERIFIER_MAX_TOKENS_PER_REQUEST = 4000
VERIFIER_DAILY_TOKEN_BUDGET = 100000
VERIFIER_CIRCUIT_FAILS = 5
VERIFIER_CIRCUIT_WINDOW_S = 60
VERIFIER_CIRCUIT_COOLDOWN_S = 30
VERIFIER_TIMEOUT_MS = 8000

# Provider pipeline configuration
VERIFIER_PROVIDERS = os.getenv("VERIFIER_PROVIDERS", "local_rules").strip() or "local_rules"
# Per-provider call timebox (ms)
VERIFIER_PROVIDER_TIMEOUT_MS = int(os.getenv("VERIFIER_PROVIDER_TIMEOUT_MS", "1600") or "1600")

# Per-provider breaker config
VERIFIER_PROVIDER_BREAKER_FAILS = int(os.getenv("VERIFIER_PROVIDER_BREAKER_FAILS", "5") or "5")
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
VERIFIER_ADAPTIVE_HALFLIFE_S = int(os.getenv("VERIFIER_ADAPTIVE_HALFLIFE_S", "120") or "120")

# Minimum samples before reordering (avoid thrash)
VERIFIER_ADAPTIVE_MIN_SAMPLES = int(os.getenv("VERIFIER_ADAPTIVE_MIN_SAMPLES", "5") or "5")

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
VERIFIER_RESULT_CACHE_ENABLED = os.getenv("VERIFIER_RESULT_CACHE_ENABLED", "1").strip() == "1"

# Optional Redis for cross-process cache. If empty, in-memory only.
VERIFIER_RESULT_CACHE_URL = os.getenv("VERIFIER_RESULT_CACHE_URL", "").strip()

# TTL in seconds for cache entries (both safe and unsafe)
VERIFIER_RESULT_CACHE_TTL_SECONDS = int(
    os.getenv("VERIFIER_RESULT_CACHE_TTL_SECONDS", "86400") or "0"
)

# Reuse ingress verification for matching egress requests (opt-in; on by default)
VERIFIER_EGRESS_REUSE_ENABLED = os.getenv("VERIFIER_EGRESS_REUSE_ENABLED", "1").strip() == "1"

# TTL for reuse entries (short-lived, per-request)
VERIFIER_EGRESS_REUSE_TTL_SECONDS = int(
    os.getenv("VERIFIER_EGRESS_REUSE_TTL_SECONDS", "300") or "300"
)

# Shadow-call alternate providers without changing decisions
VERIFIER_SANDBOX_ENABLED = os.getenv("VERIFIER_SANDBOX_ENABLED", "1").strip() == "1"
# Fraction of requests that trigger sandbox (0..1)
VERIFIER_SANDBOX_SAMPLE_RATE = float(os.getenv("VERIFIER_SANDBOX_SAMPLE_RATE", "0.05") or "0.05")
# Timebox for each shadow call in ms (kept tight)
VERIFIER_SANDBOX_TIMEOUT_MS = int(os.getenv("VERIFIER_SANDBOX_TIMEOUT_MS", "500") or "500")
# Max simultaneous shadow calls
VERIFIER_SANDBOX_MAX_CONCURRENCY = int(os.getenv("VERIFIER_SANDBOX_MAX_CONCURRENCY", "2") or "2")
# In tests, run synchronously (await) so assertions can see results
VERIFIER_SANDBOX_SYNC_FOR_TESTS = os.getenv("VERIFIER_SANDBOX_SYNC_FOR_TESTS", "0").strip() == "1"
# Cap number of sandbox results attached to audit/headers
VERIFIER_SANDBOX_MAX_RESULTS = int(os.getenv("VERIFIER_SANDBOX_MAX_RESULTS", "3") or "3")

# Emit metrics when sandbox results disagree with the primary decision.
VERIFIER_SANDBOX_DIFF_ENABLED = os.getenv("VERIFIER_SANDBOX_DIFF_ENABLED", "1").strip() == "1"

# Attach a compact summary to headers/audit when diffs occur (off by default).
VERIFIER_SANDBOX_DIFF_ATTACH_HEADER = (
    os.getenv("VERIFIER_SANDBOX_DIFF_ATTACH_HEADER", "0").strip() == "1"
)

# If attaching, cap how many items we surface.
VERIFIER_SANDBOX_DIFF_MAX_ATTACH = int(os.getenv("VERIFIER_SANDBOX_DIFF_MAX_ATTACH", "2") or "2")

# Only consider diffs when the primary is decisive (safe/unsafe).
VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE = (
    os.getenv("VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE", "1").strip() == "1"
)

# Randomly emit an audit event when a diff happens (0..1). 0 disables.
VERIFIER_SANDBOX_DIFF_AUDIT_RATE = float(
    os.getenv("VERIFIER_SANDBOX_DIFF_AUDIT_RATE", "0.0") or "0.0"
)

# Anthropic provider (optional)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
VERIFIER_ANTHROPIC_MODEL = os.getenv("VERIFIER_ANTHROPIC_MODEL", "claude-3-haiku").strip()

# --- Verifier harm-cache persistence (optional Redis) ---
VERIFIER_HARM_CACHE_URL = os.getenv("VERIFIER_HARM_CACHE_URL", "").strip()
# Days to keep a harmful fingerprint in the cache (default 90 days)
VERIFIER_HARM_TTL_DAYS = int(os.getenv("VERIFIER_HARM_TTL_DAYS", "90") or "90")

# Hidden-text scanning (opt-in)
HIDDEN_TEXT_SCAN = os.getenv("HIDDEN_TEXT_SCAN", "0").strip() == "1"
# Soft size cap for scans (bytes); 0 disables cap
HIDDEN_TEXT_SCAN_MAX_BYTES = int(os.getenv("HIDDEN_TEXT_SCAN_MAX_BYTES", "1048576") or "0")

# Enable policy hook: when 1 and a rule matches, set decision to clarify/deny.
HIDDEN_TEXT_POLICY = os.getenv("HIDDEN_TEXT_POLICY", "0").strip() == "1"

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

# Cap bytes for egress inspection peek (0 disables)
EGRESS_INSPECT_MAX_BYTES = int(os.getenv("EGRESS_INSPECT_MAX_BYTES", "4096") or "4096")

IDEMP_ENABLED = os.getenv("IDEMP_ENABLED", "true").lower() == "true"
IDEMP_METHODS = tuple(os.getenv("IDEMP_METHODS", "POST,PUT").replace(" ", "").split(","))
IDEMP_TTL_SECONDS = int(os.getenv("IDEMP_TTL_SECONDS", "120"))
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
IDEMP_RECENT_ZSET_MAX = int(os.getenv("IDEMP_RECENT_ZSET_MAX", "5000"))

_raw_idempotency_backend = os.getenv("IDEMPOTENCY_BACKEND", "memory").strip().lower()
IDEMPOTENCY_BACKEND: Literal["memory", "redis"] = (
    cast(Literal["memory", "redis"], _raw_idempotency_backend)
    if _raw_idempotency_backend in {"memory", "redis"}
    else "memory"
)

REDIS_URL: str = os.getenv("REDIS_URL", IDEMP_REDIS_URL)
REDIS_SOCKET_TIMEOUT_S: float = float(os.getenv("REDIS_SOCKET_TIMEOUT_S", "2.5"))
REDIS_SOCKET_CONNECT_TIMEOUT_S: float = float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT_S", "2.0"))
REDIS_HEALTHCHECK_INTERVAL_S: int = int(os.getenv("REDIS_HEALTHCHECK_INTERVAL_S", "15"))

_DEFAULT_PURGE_SECRET = base64.b64encode(b"insecure-test-secret").decode("ascii")
PURGE_SIGNING_SECRET: str = (
    os.getenv("PURGE_SIGNING_SECRET", _DEFAULT_PURGE_SECRET).strip() or _DEFAULT_PURGE_SECRET
)
PURGE_KEY_ID: str = os.getenv("PURGE_KEY_ID", "default-hmac").strip() or "default-hmac"
PURGE_ED25519_PRIV: str = os.getenv("PURGE_ED25519_PRIV", "").strip()
RETENTION_WORKER_ENABLED: bool = os.getenv("RETENTION_WORKER_ENABLED", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
RETENTION_MAX_IDS_PER_RUN: int = int(os.getenv("RETENTION_MAX_IDS_PER_RUN", "100") or "100")
RETENTION_AUDIT_SQL_ENABLED: bool = os.getenv(
    "RETENTION_AUDIT_SQL_ENABLED", "0"
).strip().lower() in {"1", "true", "yes", "on"}

# Webhook retry/DLQ settings
WH_REDIS_PREFIX: str = os.getenv("WH_REDIS_PREFIX", "whq")
WH_MAX_ATTEMPTS: int = int(os.getenv("WH_MAX_ATTEMPTS", "5"))
WH_RETRY_BASE_S: float = float(os.getenv("WH_RETRY_BASE_S", "1.0"))
WH_RETRY_FACTOR: float = float(os.getenv("WH_RETRY_FACTOR", "2.0"))
WH_RETRY_JITTER_S: float = float(os.getenv("WH_RETRY_JITTER_S", "0.250"))
WH_RETRY_DRAIN_BATCH: int = int(os.getenv("WH_RETRY_DRAIN_BATCH", "8"))
# Max sleep between readiness checks when waiting for the next due job
WH_RETRY_IDLE_SLEEP_MAX_S: float = float(os.getenv("WH_RETRY_IDLE_SLEEP_MAX_S", "2.0"))
WH_HTTP_TIMEOUT_S: float = float(os.getenv("WH_HTTP_TIMEOUT_S", "3.0"))
# TTL for the singleton worker lock, renewed during work and idle waits.
WH_WORKER_LOCK_TTL_S: float = float(os.getenv("WH_WORKER_LOCK_TTL_S", "15.0"))

IDEMPOTENCY_TTL_S: int = int(os.getenv("IDEMPOTENCY_TTL_S", "300"))
