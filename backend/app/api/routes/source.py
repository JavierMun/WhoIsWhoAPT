"""Source loading and status endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.dependencies import get_settings_store
from app.ingestion import load_active_source, read_source_status
from app.models.schemas import SourceLoadStatus
from app.settings_store import SettingsStore

router = APIRouter()


@router.post("/load", response_model=SourceLoadStatus, status_code=status.HTTP_200_OK)
def load_source(
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> SourceLoadStatus:
    """Trigger ingestion for the configured active source."""
    return load_active_source(session, settings_store)


@router.get("/status", response_model=SourceLoadStatus)
def source_status(
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> SourceLoadStatus:
    """Return ingestion status and record counts for the active source."""
    source_name = settings_store.load().active_source
    return read_source_status(session, source_name)
