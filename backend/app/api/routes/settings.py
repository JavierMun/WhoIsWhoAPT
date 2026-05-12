"""Application settings endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app import scheduler
from app.dependencies import get_settings_store
from app.models.schemas import ApplicationSettings
from app.settings_store import SettingsStore

router = APIRouter()


@router.get("", response_model=ApplicationSettings)
def read_settings(store: Annotated[SettingsStore, Depends(get_settings_store)]) -> ApplicationSettings:
    """Return persisted application settings."""
    return store.load()


@router.put("", response_model=ApplicationSettings, status_code=status.HTTP_200_OK)
def update_settings(
    settings: ApplicationSettings,
    store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ApplicationSettings:
    """Persist application settings and return the saved value."""
    saved = store.save(settings)
    hours = (
        saved.opencti.update_frequency_hours
        if saved.active_source == "opencti"
        else saved.mitre.update_frequency_hours
    )
    scheduler.reschedule(hours)
    return saved
