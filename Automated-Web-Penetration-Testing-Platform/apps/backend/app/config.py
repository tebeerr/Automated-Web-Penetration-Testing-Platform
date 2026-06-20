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

    # Database — SQLite default for host-only dev; swap for Postgres in prod.
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"

    # Auth
    JWT_SECRET: str = Field(default="dev-only-change-me-in-production-please", min_length=8)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_MINUTES: int = 60 * 24

    # Rate limiting
    RATE_LIMIT_PER_MIN: int = 60

    # Scan engine knobs
    SCAN_TIMEOUT_SECONDS: int = 600
    SCAN_REQUEST_DELAY_MS: int = 200
    SCAN_USER_AGENT: str = "Sentinel-Scanner/0.1 (+https://sentinel.local)"

    # Reports
    REPORTS_DIR: str = "./reports"

    # Domain verification toggle — when False, scans skip the verified-target check.
    REQUIRE_VERIFIED_TARGET: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
