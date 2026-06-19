from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # API
    API_TITLE: str = "Sentinel Pentest Hub API"
    API_VERSION: str = "0.1.0"
    DEBUG: bool = False
    FRONTEND_URL: str = "http://localhost:5173"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel"

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # Auth
    JWT_SECRET: str = Field(default="change-me-in-production", min_length=8)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_MINUTES: int = 60 * 24

    # Rate limiting
    RATE_LIMIT_PER_MIN: int = 60

    # Scanner integrations
    ZAP_API_URL: str = "http://zap:8080"
    ZAP_API_KEY: str = ""

    # LLM
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    LLM_PROVIDER: str = "anthropic"
    LLM_MODEL: str = "claude-sonnet-4-6"

    # Reports
    REPORTS_DIR: str = "/app/reports"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
