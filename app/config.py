from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized runtime configuration.
    Loads from environment and optional .env file (if present).
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # App
    APP_ENV: str = Field(default="dev")
    APP_NAME: str = Field(default="llm-guardrail-api-next")
    APP_VERSION: str = Field(default="0.3.0")
    LOG_LEVEL: str = Field(default="INFO")
    PORT: int = Field(default=8080)

    # Guardrail / verifier (placeholder for future expansion)
    VERIFIER_MODE: str = Field(default="never")  # "auto" | "never"

    # Security (API key)
    API_KEY: Optional[str] = Field(default=None)
    API_KEYS: Optional[str] = Field(default=None)

    # Header names
    API_KEY_HEADER_NAME: str = Field(default="X-API-Key")
    AUTH_BEARER_PREFIX: str = Field(default="Bearer ")

    # Redaction controls
    REDACT_SECRETS: bool = Field(default=True, description="Mask known secret patterns")
    REDACT_OPENAI_MASK: str = Field(default="[REDACTED:OPENAI_KEY]")
    REDACT_AWS_AKID_MASK: str = Field(default="[REDACTED:AWS_ACCESS_KEY_ID]")
    REDACT_PEM_MASK: str = Field(default="[REDACTED:PRIVATE_KEY]")

    # Prompt-size limits (characters)
    MAX_PROMPT_CHARS: int = Field(default=16000)

    # Rate limit (per API key/IP)
    RATE_LIMIT_ENABLED: bool = Field(default=False)
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    RATE_LIMIT_BURST: int = Field(default=60)

    # CORS
    CORS_ALLOW_ORIGINS: str = Field(default="*")  # comma-separated or "*"


settings = Settings()

