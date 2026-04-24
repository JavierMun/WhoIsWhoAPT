"""Comparison API endpoints."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analytics.comparison import (
    ComparisonResult as AnalyticsComparisonResult,
)
from app.analytics.comparison import (
    EntityTechniqueSet,
    compare_against_entities,
    compare_pair,
)
from app.database import get_db_session
from app.dependencies import get_settings_store
from app.errors import AppError
from app.models import entities
from app.models.schemas import ActorComparisonRequest, ComparisonResponse, ComparisonResult, CustomComparisonRequest
from app.settings_store import SettingsStore

router = APIRouter()


@router.post("/actor", response_model=ComparisonResponse)
def compare_actor(
    request: ActorComparisonRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ComparisonResponse:
    """Compare one actor against all actors, or directly against another actor."""
    active_source = settings_store.load().active_source
    actor = _get_actor(session, request.actor_id)
    input_techniques = _technique_ids(actor.techniques)

    if request.target_actor_id is not None:
        target = _get_actor(session, request.target_actor_id)
        target_entity = _actor_entity(target)
        candidates = _actor_candidates(session, active_source)
        weights = _rarity_weights_for_direct_comparison(candidates, request.metric)
        result = compare_pair(input_techniques, target_entity, metric=request.metric, weights=weights)
        return ComparisonResponse(
            input_id=actor.id,
            input_name=actor.name,
            input_type="actor",
            metric=request.metric,
            results=[_result_schema(result)],
        )

    candidates = _actor_candidates(session, active_source)
    results = compare_against_entities(
        input_techniques,
        candidates,
        metric=request.metric,
        top_n=request.top_n,
        exclude_entity_id=None if request.include_self else actor.id,
    )
    return ComparisonResponse(
        input_id=actor.id,
        input_name=actor.name,
        input_type="actor",
        metric=request.metric,
        results=[_result_schema(result) for result in results],
    )


@router.post("/custom", response_model=ComparisonResponse)
def compare_custom_set(
    request: CustomComparisonRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ComparisonResponse:
    """Compare an inline or saved custom TTP set against all actors."""
    active_source = settings_store.load().active_source
    input_id: str | None = None
    input_name = request.name or "Custom TTP Set"

    if request.custom_set_id is not None:
        custom_set = session.get(entities.CustomTTPSet, request.custom_set_id)
        if custom_set is None:
            raise AppError("Custom TTP set not found", status_code=404)
        input_id = custom_set.id
        input_name = custom_set.name
        input_techniques = set(custom_set.technique_ids)
    elif request.technique_ids is not None:
        _validate_technique_ids(session, request.technique_ids)
        input_techniques = set(request.technique_ids)
    else:
        raise AppError("Provide either custom_set_id or technique_ids", status_code=422)

    results = compare_against_entities(
        input_techniques,
        _actor_candidates(session, active_source),
        metric=request.metric,
        top_n=request.top_n,
    )
    return ComparisonResponse(
        input_id=input_id,
        input_name=input_name,
        input_type="custom_set",
        metric=request.metric,
        results=[_result_schema(result) for result in results],
    )


def _get_actor(session: Session, actor_id: str) -> entities.Actor:
    """Return an actor row or raise a clean API error."""
    actor = session.get(entities.Actor, actor_id)
    if actor is None:
        raise AppError("Actor not found", status_code=404)
    return actor


def _actor_candidates(session: Session, source: str) -> list[EntityTechniqueSet]:
    """Load actor candidates for the active source."""
    rows = session.scalars(select(entities.Actor).where(entities.Actor.source == source)).all()
    return [_actor_entity(row) for row in rows]


def _actor_entity(actor: entities.Actor) -> EntityTechniqueSet:
    """Convert an actor ORM row to a comparable analytics entity."""
    return EntityTechniqueSet(
        id=actor.id,
        name=actor.name,
        source=actor.source,
        techniques=_technique_ids(actor.techniques),
    )


def _technique_ids(raw_refs: list[dict[str, Any]]) -> set[str]:
    """Extract technique IDs from stored TechniqueRef JSON payloads."""
    return {str(ref["technique_id"]) for ref in raw_refs if ref.get("technique_id")}


def _validate_technique_ids(session: Session, technique_ids: list[str]) -> None:
    """Ensure inline custom comparison technique IDs exist locally."""
    if not technique_ids:
        raise AppError("Custom comparison must include at least one technique", status_code=422)

    requested_ids = set(technique_ids)
    existing_ids = set(
        session.scalars(select(entities.Technique.technique_id).where(entities.Technique.technique_id.in_(requested_ids)))
    )
    invalid_ids = sorted(requested_ids - existing_ids)
    if invalid_ids:
        raise AppError("Unknown technique IDs", status_code=422, detail={"technique_ids": invalid_ids})


def _rarity_weights_for_direct_comparison(
    candidates: list[EntityTechniqueSet],
    metric: str,
) -> dict[str, float]:
    """Return rarity weights for direct comparisons when the weighted metric is requested."""
    if metric != "jaccard_weighted":
        return {}

    from app.analytics.similarity import rarity_weights

    return rarity_weights([candidate.techniques for candidate in candidates])


def _result_schema(result: AnalyticsComparisonResult) -> ComparisonResult:
    """Convert an analytics result dataclass into the API response schema."""
    return ComparisonResult(
        matched_entity_id=result.matched_entity_id,
        matched_entity_name=result.matched_entity_name,
        matched_entity_source=result.matched_entity_source,
        score=result.score,
        shared_techniques=result.shared_techniques,
        unique_to_input=result.unique_to_input,
        unique_to_matched_entity=result.unique_to_matched_entity,
    )
