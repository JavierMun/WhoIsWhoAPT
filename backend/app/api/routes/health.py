"""Health-check endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.config import AppConfig, get_config

router = APIRouter()


class HealthResponse(BaseModel):
    """Health status returned by the backend."""

    status: str = Field(examples=["ok"])
    service: str
    environment: str
    timestamp: datetime


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Return a lightweight liveness response."""
    config: AppConfig = get_config()
    return HealthResponse(
        status="ok",
        service=config.app_name,
        environment=config.environment,
        timestamp=datetime.now(timezone.utc),  # noqa: UP017 - local dev still supports Python 3.10.
    )
