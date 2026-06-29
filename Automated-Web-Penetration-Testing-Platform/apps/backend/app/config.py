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

    # ── Pipeline Configuration ───────────────────────────────
    PIPELINE_MODE: str = "web_only"
    # Options: "web_only" | "recon_web" | "full_pipeline"

    # ── Nmap Configuration ───────────────────────────────────
    NMAP_PATH: str = "/usr/bin/nmap"
    NMAP_SCAN_ARGS: str = "-sV -sC --top-ports 1000 -T4"
    NMAP_VULN_ARGS: str = "--script vuln"
    NMAP_OS_DETECTION: bool = True          # requires root
    NMAP_TIMEOUT_SECONDS: int = 300

    # ── Metasploit RPC Configuration ─────────────────────────
    MSF_RPC_HOST: str = "127.0.0.1"
    MSF_RPC_PORT: int = 55553
    MSF_RPC_PASSWORD: str = "sentinel_msf"  # CHANGE IN PRODUCTION
    MSF_RPC_SSL: bool = True
    MSF_WORKSPACE: str = "sentinel"

    # ── Exploitation Safety Guards ───────────────────────────
    MSF_EXPLOIT_ENABLED: bool = False       # OFF by default
    MSF_SAFE_EXPLOITS_ONLY: bool = True     # only non-destructive
    MSF_MAX_EXPLOIT_ATTEMPTS: int = 5
    MSF_SESSION_TIMEOUT: int = 120          # auto-close sessions
    MSF_ALLOWED_MODULE_PREFIXES: list[str] = [
        "auxiliary/scanner/",
        "auxiliary/gather/",
        "exploit/multi/http/",
        "exploit/unix/webapp/",
    ]
    MSF_BLOCKED_MODULES: list[str] = [
        "auxiliary/dos/",                    # deny of service
        "exploit/windows/smb/ms17_010",      # too destructive
    ]

    # ── Post-Exploitation ────────────────────────────────────
    POST_EXPLOIT_ENABLED: bool = False      # OFF by default
    POST_EXPLOIT_ACTIONS: list[str] = [
        "sysinfo",
        "getuid",
        "ifconfig",
        "route",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
