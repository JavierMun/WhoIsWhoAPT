"""Runtime configuration for the backend service."""

from functools import lru_cache
from pathlib import Path
from typing import Literal, cast

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Environment-driven process configuration."""

    app_name: str = "WhoIsWhoAPT"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "sqlite:////data/whoiswhoapt.db"
    settings_file: Path = Path("/data/config.json")
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="WHOISWHOAPT_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    @property
    def normalized_log_level(self) -> Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        """Return a valid logging level name."""
        level = self.log_level.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            return "INFO"
        return cast(Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], level)


@lru_cache
def get_config() -> AppConfig:
    """Return cached runtime configuration."""
    return AppConfig()
