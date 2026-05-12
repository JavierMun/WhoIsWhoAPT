"""Dependency providers for FastAPI routes."""

from app.config import AppConfig, get_config
from app.settings_store import SettingsStore


def get_app_config() -> AppConfig:
    """Return application process configuration."""
    return get_config()


def get_settings_store() -> SettingsStore:
    """Return the settings persistence service."""
    return SettingsStore(get_config().settings_file)

