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

    # Header names (kept simple for now)
    API_KEY_HEADER_NAME: str = Field(default="X-API-Key")
    AUTH_BEARER_PREFIX: str = Field(default="Bearer ")


settings = Settings()
