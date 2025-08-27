from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
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

    # --- Limits ---
    MAX_PROMPT_CHARS: int = 20000
    OUTPUT_MAX_CHARS: int = 20000

    # --- Redaction & Audit ---
    REDACT_SECRETS: bool = True
    AUDIT_ENABLED: bool = True
    AUDIT_SAMPLE_RATE: float = 0.2
    AUDIT_MAX_TEXT_CHARS: int = 200

    # --- Rate limit ---
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 60
    RATE_LIMIT_BACKEND: str = "memory"  # "memory" | "redis"
    REDIS_URL: Optional[str] = None     # e.g. redis://localhost:6379/0

    # --- Metrics / tracing ---
    METRICS_ENABLED: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None

    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# Small DTOs used elsewhere
class ServiceInfo(BaseModel):
    service: str = "llm-guardrail-api-next"
    env: str = Field(default=os.environ.get("ENV", "dev"))

