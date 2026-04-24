"""JSON-backed settings persistence."""

import json
from pathlib import Path

from pydantic import ValidationError

from app.errors import AppError
from app.models.schemas import ApplicationSettings


class SettingsStore:
    """Load and save user-editable application settings."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> ApplicationSettings:
        """Load settings from disk or return defaults."""
        if not self.path.exists():
            return ApplicationSettings()

        try:
            with self.path.open("r", encoding="utf-8") as config_file:
                return ApplicationSettings.model_validate(json.load(config_file))
        except json.JSONDecodeError as exc:
            raise AppError("Configuration file is invalid JSON", status_code=500) from exc
        except ValidationError as exc:
            raise AppError("Configuration file failed validation", status_code=500, detail=exc.errors()) from exc

    def save(self, settings: ApplicationSettings) -> ApplicationSettings:
        """Persist settings to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as config_file:
            config_file.write(settings.model_dump_json(indent=2))
            config_file.write("\n")
        return settings

