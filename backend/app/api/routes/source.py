"""Source loading and status endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.dependencies import get_settings_store
from app.errors import AppError
from app.ingestion import load_active_source, read_source_status
from app.models import entities
from app.models.schemas import (
    ConnectionTestRequest,
    ConnectionTestResult,
    EnrichmentOptions,
    OpenCTIReport,
    ReportTechniquesResponse,
    SourceLoadStatus,
)
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


@router.get("/reports", response_model=list[OpenCTIReport])
def search_reports(
    q: Annotated[str, Query(min_length=1)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> list[OpenCTIReport]:
    """Search OpenCTI reports by name. Requires OpenCTI to be the active source."""
    settings = settings_store.load()
    if settings.active_source != "opencti":
        raise AppError("Report search requires OpenCTI to be the active source", status_code=400)
    cfg = settings.opencti
    if not cfg.url or not cfg.api_token:
        raise AppError("OpenCTI is not configured", status_code=400)
    from app.sources.opencti import OpenCTIAdapter

    adapter = OpenCTIAdapter(str(cfg.url), cfg.api_token)
    results = adapter.search_reports(q)
    return [OpenCTIReport(**r) for r in results]


@router.get("/reports/{report_id}/techniques", response_model=ReportTechniquesResponse)
def report_techniques(
    report_id: str,
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ReportTechniquesResponse:
    """Extract ATT&CK technique IDs from an OpenCTI report."""
    settings = settings_store.load()
    if settings.active_source != "opencti":
        raise AppError("Report ingestion requires OpenCTI to be the active source", status_code=400)
    cfg = settings.opencti
    if not cfg.url or not cfg.api_token:
        raise AppError("OpenCTI is not configured", status_code=400)
    from app.sources.opencti import OpenCTIAdapter

    adapter = OpenCTIAdapter(str(cfg.url), cfg.api_token)
    name, technique_ids = adapter.fetch_report_technique_ids(report_id)
    return ReportTechniquesResponse(
        report_id=report_id,
        report_name=name,
        technique_ids=technique_ids,
    )


@router.post("/test-connection", response_model=ConnectionTestResult)
def test_connection(body: ConnectionTestRequest) -> ConnectionTestResult:
    """Test an OpenCTI connection using the supplied URL and token.

    Always returns HTTP 200 — check the 'ok' field for the actual result.
    Credentials are used only for this request and never persisted here.
    """
    try:
        from app.sources.opencti import OpenCTIAdapter

        adapter = OpenCTIAdapter(body.url, body.api_token)
        adapter.test_connection()
        return ConnectionTestResult(ok=True)
    except AppError as exc:
        return ConnectionTestResult(ok=False, detail=exc.message)
    except Exception as exc:
        return ConnectionTestResult(ok=False, detail=str(exc))


@router.get("/enrichment-options", response_model=EnrichmentOptions)
def enrichment_options(
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> EnrichmentOptions:
    """Return sorted distinct sector and country values for the active source.

    Used by the Compare UI to populate the enrichment filter dropdowns.
    Only actors with at least one value are considered.
    """
    active_source = settings_store.load().active_source
    rows = session.execute(
        select(entities.Actor.target_sectors, entities.Actor.target_countries).where(
            entities.Actor.source == active_source
        )
    ).all()

    sectors: set[str] = set()
    countries: set[str] = set()
    for actor_sectors, actor_countries in rows:
        sectors.update(s for s in (actor_sectors or []) if s)
        countries.update(c for c in (actor_countries or []) if c)

    return EnrichmentOptions(
        sectors=sorted(sectors, key=str.lower),
        countries=sorted(countries, key=str.lower),
    )
