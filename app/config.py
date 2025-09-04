# app/config.py
from __future__ import annotations

import os
from typing import List, Literal, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


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
    JWT_JWKS_URL: Optional[str] = None          # For RS256 OIDC/JWKS
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
    verifier_enabled: bool = Field(
        default=False, description="Enable verifier flow"
    )
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
    REDIS_URL: Optional[str] = None     # e.g. redis://localhost:6379/0

    # --- Metrics / tracing ---
    METRICS_ENABLED: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None

    # --- HTTP / CORS / Telemetry toggles (new) ---
    CORS_ALLOW_ORIGINS: str = Field(default="*")  # comma-separated, or "*"
    ENABLE_LATENCY_HISTOGRAM: bool = Field(default=True)

    # --- Security headers (new) ---
    SECURITY_HEADERS_ENABLED: bool = Field(default=True)
    ADD_COOP: bool = Field(default=True)                # Cross-Origin-Opener-Policy
    ADD_PERMISSIONS_POLICY: bool = Field(default=True)  # Permissions-Policy
    ADD_HSTS: bool = Field(default=True)                 # Strict-Transport-Security
    HSTS_MAX_AGE: int = Field(default=15552000)          # 180 days

    # --- Compliance / Privacy (new) ---
    COMPLIANCE_ENABLED: bool = Field(default=True)
    DATA_RETENTION_DAYS: int = Field(default=30)         # for docs/policy, not enforced
    PII_SALT: str = Field(default="change-me")           # for salted hashing
    PII_HASH_ALGO: str = Field(default="sha256")         # sha256 only for now
    PII_EMAIL_HASH_ENABLED: bool = Field(default=True)
    PII_PHONE_HASH_ENABLED: bool = Field(default=True)

    # --- Header names (new) ---
    API_KEY_HEADER: str = Field(default="X-API-Key")
    TENANT_HEADER: str = Field(default="X-Tenant")
    BOT_HEADER: str = Field(default="X-Bot")

    # --- Logging (new) ---
    LOG_JSON: bool = Field(default=True)
    LOG_LEVEL: str = Field(default="INFO")

    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

def get_settings() -> Settings:
    return Settings()


class ServiceInfo(BaseModel):
    service: str = "llm-guardrail-api-next"
    env: str = Field(default=os.environ.get("ENV", "dev"))
