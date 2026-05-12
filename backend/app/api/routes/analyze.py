"""Incident analysis API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.routes.compare import compare_custom_techniques
from app.database import get_db_session
from app.dependencies import get_settings_store
from app.models.schemas import ComparisonResponse, IncidentAnalysisRequest
from app.settings_store import SettingsStore

router = APIRouter()


@router.post("/incident", response_model=ComparisonResponse)
def analyze_incident(
    request: IncidentAnalysisRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ComparisonResponse:
    """Analyze observed incident TTPs against the active actor dataset."""
    return compare_custom_techniques(request, session, settings_store)
