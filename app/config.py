from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_ENV: str = Field(default="dev")
    APP_NAME: str = Field(default="llm-guardrail-api-next")
    LOG_LEVEL: str = Field(default="INFO")
    PORT: int = Field(default=8080)

    VERIFIER_MODE: str = Field(default="never")  # "auto" | "never"

settings = Settings()
