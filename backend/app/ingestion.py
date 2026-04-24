"""Source ingestion orchestration and SQLite persistence."""

from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.errors import AppError
from app.models import entities
from app.models.schemas import Actor, Campaign, Software, SourceLoadStatus, Technique
from app.settings_store import SettingsStore
from app.sources.base import BaseSource
from app.sources.mitre import MitreSource


def get_source_adapter(source: str) -> BaseSource:
    """Return the source adapter for a supported primary source."""
    if source == "mitre":
        return MitreSource()
    raise AppError(f"Source '{source}' is not implemented", status_code=400)


def load_active_source(session: Session, settings_store: SettingsStore) -> SourceLoadStatus:
    """Load the active primary source and replace its normalized dataset."""
    source_name = settings_store.load().active_source
    adapter = get_source_adapter(source_name)

    _upsert_status(session, source_name, status="running", error=None)
    session.commit()

    try:
        techniques = adapter.fetch_techniques()
        actors = adapter.fetch_actors()
        campaigns = adapter.fetch_campaigns()
        software = adapter.fetch_software()
        version = adapter.get_source_version()

        _replace_source_data(session, source_name, actors, campaigns, software, techniques)
        status = _upsert_status(
            session,
            source_name,
            status="completed",
            version=version,
            last_loaded_at=datetime.now(timezone.utc),  # noqa: UP017 - local dev still supports Python 3.10.
            error=None,
            actor_count=len(actors),
            campaign_count=len(campaigns),
            software_count=len(software),
            technique_count=len(techniques),
        )
        session.commit()
        return _status_schema(status)
    except Exception as exc:
        session.rollback()
        status = _upsert_status(session, source_name, status="failed", error=str(exc))
        session.commit()
        if isinstance(exc, AppError):
            raise exc
        raise AppError("Source ingestion failed", status_code=500, detail=str(exc)) from exc


def read_source_status(session: Session, source_name: str) -> SourceLoadStatus:
    """Return persisted ingestion status for a source."""
    status = session.get(entities.SourceLoadStatus, source_name)
    if status is None:
        return SourceLoadStatus(source=source_name, status="never_loaded")
    return _status_schema(status)


def _replace_source_data(
    session: Session,
    source_name: str,
    actors: list[Actor],
    campaigns: list[Campaign],
    software: list[Software],
    techniques: list[Technique],
) -> None:
    """Replace all source-backed rows for the active primary source."""
    session.execute(delete(entities.Actor).where(entities.Actor.source == source_name))
    session.execute(delete(entities.Campaign).where(entities.Campaign.source == source_name))
    session.execute(delete(entities.Software).where(entities.Software.source == source_name))

    # Techniques are currently MITRE ATT&CK techniques regardless of primary
    # source, so clear the table before reloading the active ATT&CK corpus.
    session.execute(delete(entities.Technique))

    for technique in techniques:
        session.add(entities.Technique(**technique.model_dump()))
    for actor in actors:
        data = actor.model_dump()
        data["techniques"] = [ref.model_dump() for ref in actor.techniques]
        session.add(entities.Actor(**data))
    for campaign in campaigns:
        data = campaign.model_dump()
        data["techniques"] = [ref.model_dump() for ref in campaign.techniques]
        session.add(entities.Campaign(**data))
    for item in software:
        data = item.model_dump()
        data["techniques"] = [ref.model_dump() for ref in item.techniques]
        session.add(entities.Software(**data))


def _upsert_status(session: Session, source_name: str, **values: object) -> entities.SourceLoadStatus:
    """Create or update a source status row."""
    status = session.scalar(select(entities.SourceLoadStatus).where(entities.SourceLoadStatus.source == source_name))
    if status is None:
        status = entities.SourceLoadStatus(source=source_name)
        session.add(status)
    for key, value in values.items():
        setattr(status, key, value)
    return status


def _status_schema(status: entities.SourceLoadStatus) -> SourceLoadStatus:
    """Convert an ORM status row to its API schema."""
    return SourceLoadStatus(
        source=status.source,
        status=status.status,
        version=status.version,
        last_loaded_at=status.last_loaded_at,
        error=status.error,
        actor_count=status.actor_count,
        campaign_count=status.campaign_count,
        software_count=status.software_count,
        technique_count=status.technique_count,
    )
