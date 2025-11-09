# app/config.py
from __future__ import annotations

import json
import os
from typing import List, Literal, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
GIT_SHA = os.getenv("GIT_SHA", "")
BUILD_TS = os.getenv("BUILD_TS", "")


class Settings(BaseSettings):
    # --- Identity / Build ---
    APP_NAME: str = Field(default="LLM Guardrail API")
    ENV: str = Field(default=os.environ.get("ENV", "dev"))
    VERSION: str = Field(default=os.environ.get("VERSION", "0.1.0"))
    GIT_SHA: str = Field(default=os.environ.get("GIT_SHA", "unknown"))

    # --- Core ---
    API_KEY: str | None = None

    # --- Auth mode: "api_key" (default) or "jwt" ---
    AUTH_MODE: str = Field(default="api_key")

    # JWT (pick one verification method)
    JWT_JWKS_URL: Optional[str] = None  # For RS256 OIDC/JWKS
    JWT_ISSUER: Optional[str] = None
    JWT_AUDIENCE: Optional[str] = None
    JWT_ALGORITHMS: List[str] = Field(default_factory=lambda: ["RS256", "HS256"])

    # HS256 option (when you control the issuer)
    JWT_HS256_SECRET: Optional[str] = None

    # --- Policy ---
    POLICY_AUTORELOAD: bool = Field(default=True)
    POLICY_RULES_PATH: str = Field(default=os.environ.get("POLICY_RULES_PATH", ""))
    # Default action when an injection/jailbreak is detected (unless a rule overrides it)
    default_injection_action: Literal["block", "clarify"] = Field(
        default="block",
        description="Default action for injection/jailbreak hits",
    )

    # --- Verifier (gray-area routing) ---
    verifier_enabled: bool = Field(default=False, description="Enable verifier flow")
    verifier_provider: Literal["mock", "openai", "anthropic", "azure"] = Field(
        default="mock", description="Which verifier adapter to use"
    )
    verifier_timeout_s: int = Field(default=8, ge=1, le=30)
    verifier_budget_cents: int = Field(default=5, ge=0)
    verifier_default_action: Literal["block", "clarify"] = Field(
        default="block", description="Fallback if verifier fails"
    )
    gray_trigger_families: list[str] = Field(
        default_factory=lambda: ["injection", "jailbreak", "illicit"],
        description="Families that may route to verifier when uncertain",
    )

    # --- Limits ---
    MAX_PROMPT_CHARS: int = 20000
    OUTPUT_MAX_CHARS: int = 20000

    # --- Redaction & Audit ---
    REDACT_SECRETS: bool = True
    AUDIT_ENABLED: bool = True
    AUDIT_SAMPLE_RATE: float = 0.2
    AUDIT_MAX_TEXT_CHARS: int = 200

    # --- Rate limit (existing contract) ---
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 60
    RATE_LIMIT_BACKEND: str = "memory"  # "memory" | "redis"
    REDIS_URL: Optional[str] = None  # e.g. redis://localhost:6379/0

    # --- Metrics / tracing ---
    METRICS_ENABLED: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None

    # --- HTTP / CORS / Telemetry toggles (new) ---
    CORS_ALLOW_ORIGINS: str = Field(default="*")  # comma-separated, or "*"
    ENABLE_LATENCY_HISTOGRAM: bool = Field(default=True)

    # --- Security headers (new) ---
    SECURITY_HEADERS_ENABLED: bool = Field(default=True)
    ADD_COOP: bool = Field(default=True)  # Cross-Origin-Opener-Policy
    ADD_PERMISSIONS_POLICY: bool = Field(default=True)  # Permissions-Policy
    ADD_HSTS: bool = Field(default=True)  # Strict-Transport-Security
    HSTS_MAX_AGE: int = Field(default=15552000)  # 180 days

    # --- Compliance / Privacy (new) ---
    COMPLIANCE_ENABLED: bool = Field(default=True)
    DATA_RETENTION_DAYS: int = Field(default=30)  # for docs/policy, not enforced
    PII_SALT: str = Field(default="change-me")  # for salted hashing
    PII_HASH_ALGO: str = Field(default="sha256")  # sha256 only for now
    PII_EMAIL_HASH_ENABLED: bool = Field(default=True)
    PII_PHONE_HASH_ENABLED: bool = Field(default=True)

    # --- Header names (new) ---
    API_KEY_HEADER: str = Field(default="X-API-Key")
    TENANT_HEADER: str = Field(default="X-Tenant")
    BOT_HEADER: str = Field(default="X-Bot")

    # --- Logging (new) ---
    LOG_JSON: bool = Field(default=True)
    LOG_LEVEL: str = Field(default="INFO")

    # --- Admin UI feature toggles ---
    ADMIN_ENABLE_GOLDEN_ONE_CLICK: bool = Field(default=False)
    DEMO_DEFAULT_BINDINGS: bool = Field(default=False)

    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


def get_settings() -> Settings:
    return Settings()


def admin_token() -> str | None:
    token = os.environ.get("ADMIN_TOKEN", "")
    return token or None


def admin_allow_remote() -> bool:
    return os.environ.get("ADMIN_ALLOW_REMOTE", "") == "1"


class ServiceInfo(BaseModel):
    service: str = "llm-guardrail-api-next"
    env: str = Field(default=os.environ.get("ENV", "dev"))


# --- Admin audit persistence ---
AUDIT_BACKEND = os.getenv("AUDIT_BACKEND", "").strip().lower()
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "").strip()
_AUDIT_REDIS_KEY_DEFAULT = "guardrail:admin_audit:v1"
AUDIT_REDIS_KEY = (
    os.getenv("AUDIT_REDIS_KEY", _AUDIT_REDIS_KEY_DEFAULT).strip() or _AUDIT_REDIS_KEY_DEFAULT
)
try:
    AUDIT_REDIS_MAXLEN = int(os.getenv("AUDIT_REDIS_MAXLEN", "50000"))
except ValueError:
    AUDIT_REDIS_MAXLEN = 50000
try:
    AUDIT_RECENT_LIMIT = int(os.getenv("AUDIT_RECENT_LIMIT", "500"))
except ValueError:
    AUDIT_RECENT_LIMIT = 500
# --- Admin UI auth / RBAC ---
ADMIN_AUTH_MODE = os.getenv("ADMIN_AUTH_MODE", "cookie")  # "disabled" | "cookie" | "oidc"
ADMIN_RBAC_DEFAULT_ROLE = os.getenv("ADMIN_RBAC_DEFAULT_ROLE", "viewer")
ADMIN_RBAC_OVERRIDES_JSON = os.getenv("ADMIN_RBAC_OVERRIDES", "{}")
try:
    ADMIN_RBAC_OVERRIDES = json.loads(ADMIN_RBAC_OVERRIDES_JSON)
except Exception:
    ADMIN_RBAC_OVERRIDES = {}

SERVICE_TOKEN_SECRET = os.getenv("SERVICE_TOKEN_SECRET", "").strip()
SERVICE_TOKEN_TTL_HOURS = int(os.getenv("SERVICE_TOKEN_TTL_HOURS", "720"))
SERVICE_TOKEN_ISSUER = os.getenv("SERVICE_TOKEN_ISSUER", "guardrail-api")
SERVICE_TOKEN_AUDIENCE = os.getenv("SERVICE_TOKEN_AUDIENCE", "guardrail-admin")
SERVICE_TOKEN_USE_REDIS = os.getenv("SERVICE_TOKEN_USE_REDIS", "").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
SERVICE_TOKEN_REDIS_PREFIX = os.getenv("SERVICE_TOKEN_REDIS_PREFIX", "guardrail:svc_tokens")


# OIDC configuration for admin UI/API session auth
def _truthy_env(name: str) -> bool:
    return (os.getenv(name, "") or "").strip().lower() in {"1", "true", "yes", "on"}


OIDC_ENABLED = _truthy_env("OIDC_ENABLED")
OIDC_ISSUER = (os.getenv("OIDC_ISSUER", "") or "").strip()
OIDC_CLIENT_ID = (os.getenv("OIDC_CLIENT_ID", "") or "").strip()
OIDC_CLIENT_SECRET = (os.getenv("OIDC_CLIENT_SECRET", "") or "").strip()
OIDC_REDIRECT_PATH = (os.getenv("OIDC_REDIRECT_PATH", "/admin/auth/callback") or "").strip()
OIDC_SCOPES = (os.getenv("OIDC_SCOPES", "openid email profile") or "").strip()
OIDC_ROLE_CLAIM = (os.getenv("OIDC_ROLE_CLAIM", "roles") or "").strip()
try:
    OIDC_ROLE_MAP = json.loads(
        os.getenv(
            "OIDC_ROLE_MAP",
            '{"admin": ["admin"], "operator": ["operator"], "viewer": ["viewer"]}',
        )
        or "{}",
    )
except Exception:
    OIDC_ROLE_MAP = {"admin": ["admin"], "operator": ["operator"], "viewer": ["viewer"]}
OIDC_DEFAULT_ROLE = (os.getenv("OIDC_DEFAULT_ROLE", "viewer") or "").strip() or "viewer"
OIDC_EMAIL_CLAIM = (os.getenv("OIDC_EMAIL_CLAIM", "email") or "").strip()
OIDC_NAME_CLAIM = (os.getenv("OIDC_NAME_CLAIM", "name") or "").strip()
OIDC_LOGOUT_URL = (os.getenv("OIDC_LOGOUT_URL", "") or "").strip()
