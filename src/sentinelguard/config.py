"""Environment-driven configuration. Every setting has a safe local default."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "SentinelGuard AI"
APP_SUBTITLE = "Enterprise Security Guardrail Auditor"
APP_VERSION = "0.1.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELGUARD_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/sentinelguard.db"
    max_upload_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    max_files_per_scan: int = Field(default=10, ge=1, le=50)
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"
    api_base_url: str = "http://localhost:8000"


@lru_cache
def get_settings() -> Settings:
    return Settings()
