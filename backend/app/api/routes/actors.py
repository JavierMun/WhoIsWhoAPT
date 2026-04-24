"""Minimal actor lookup endpoints for comparison workflows."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.dependencies import get_settings_store
from app.errors import AppError
from app.models import entities
from app.models.schemas import ActorDetail, ActorListItem, TechniqueRef
from app.settings_store import SettingsStore

router = APIRouter()


@router.get("", response_model=list[ActorListItem])
def list_actors(
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> list[ActorListItem]:
    """List actors from the active source with enough metadata to pick an ID."""
    active_source = settings_store.load().active_source
    actors = session.scalars(
        select(entities.Actor).where(entities.Actor.source == active_source).order_by(entities.Actor.name)
    )
    return [
        ActorListItem(
            id=actor.id,
            name=actor.name,
            aliases=actor.aliases,
            technique_count=len(actor.techniques),
        )
        for actor in actors
    ]


@router.get("/{actor_id}", response_model=ActorDetail)
def actor_detail(
    actor_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> ActorDetail:
    """Return actor details with normalized ATT&CK technique references."""
    actor = session.get(entities.Actor, actor_id)
    if actor is None:
        raise AppError("Actor not found", status_code=404)

    techniques = [_technique_ref(ref) for ref in actor.techniques]
    return ActorDetail(
        id=actor.id,
        name=actor.name,
        aliases=actor.aliases,
        description=actor.description,
        techniques=techniques,
        technique_count=len(techniques),
    )


def _technique_ref(raw_ref: dict[str, Any]) -> TechniqueRef:
    """Convert stored TechniqueRef JSON into its API schema."""
    return TechniqueRef(
        technique_id=str(raw_ref["technique_id"]),
        use_description=raw_ref.get("use_description"),
        detected_in_campaigns=list(raw_ref.get("detected_in_campaigns", [])),
    )
