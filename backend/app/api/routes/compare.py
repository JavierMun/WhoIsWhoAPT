"""Comparison API endpoints."""

from typing import Annotated, Any, Literal, cast

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
from app.models.schemas import (
    ActorComparisonRequest,
    ComparisonResponse,
    ComparisonResult,
    CustomComparisonRequest,
    IncidentAnalysisRequest,
    SoftwareSummary,
    TacticBreakdown,
)
from app.settings_store import SettingsStore

router = APIRouter()


@router.post("/actor", response_model=ComparisonResponse)
def compare_actor(
    request: ActorComparisonRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ComparisonResponse:
    """Compare one actor against all actors, or directly against another actor."""
    settings = settings_store.load()
    active_source = settings.active_source
    actor = _get_actor(session, request.actor_id)
    input_techniques = _technique_ids(actor.techniques)
    input_software = set(actor.software_used)
    technique_tactics = _technique_tactics(session)
    tactic_scope = _normalize_tactic_scope(request.tactics)
    software_lookup = _software_lookup(session)

    if request.target_actor_id is not None:
        target = _get_actor(session, request.target_actor_id)
        target_entity = _actor_entity(target)
        candidates = _actor_candidates(session, active_source)
        filtered_input_techniques = _filter_techniques_by_tactics(input_techniques, technique_tactics, tactic_scope)
        scoped_input_software = _software_for_tactic_scope(input_software, filtered_input_techniques, tactic_scope)
        candidates = [_filter_entity_by_tactics(candidate, technique_tactics, tactic_scope) for candidate in candidates]
        target_entity = _filter_entity_by_tactics(target_entity, technique_tactics, tactic_scope)
        weights = _rarity_weights_for_direct_comparison(candidates, request.metric)
        result = compare_pair(
            filtered_input_techniques,
            target_entity,
            metric=request.metric,
            weights=weights,
            technique_tactics=technique_tactics,
            tactic_weights=settings.scoring.tactic_weights,
            input_software=scoped_input_software,
            technique_score_weight=settings.scoring.technique_score_weight,
            software_score_weight=settings.scoring.software_score_weight,
        )
        explanation = _tactic_scope_explanation(filtered_input_techniques, target_entity.techniques, tactic_scope)
        return ComparisonResponse(
            input_id=actor.id,
            input_name=actor.name,
            input_type="actor",
            metric=request.metric,
            results=[_result_schema(result, software_lookup, explanation=explanation)],
        )

    candidates = _actor_candidates(session, active_source)
    if request.target_ids is not None:
        candidates = _target_actor_candidates(candidates, request.target_ids)
    filtered_input_techniques = _filter_techniques_by_tactics(input_techniques, technique_tactics, tactic_scope)
    scoped_input_software = _software_for_tactic_scope(input_software, filtered_input_techniques, tactic_scope)
    candidates = [_filter_entity_by_tactics(candidate, technique_tactics, tactic_scope) for candidate in candidates]
    candidate_techniques_by_id = {candidate.id: candidate.techniques for candidate in candidates}

    results = compare_against_entities(
        filtered_input_techniques,
        candidates,
        metric=request.metric,
        top_n=request.top_n,
        exclude_entity_id=None if request.include_self else actor.id,
        technique_tactics=technique_tactics,
        tactic_weights=settings.scoring.tactic_weights,
        input_software=scoped_input_software,
        technique_score_weight=settings.scoring.technique_score_weight,
        software_score_weight=settings.scoring.software_score_weight,
    )
    return ComparisonResponse(
        input_id=actor.id,
        input_name=actor.name,
        input_type="actor",
        metric=request.metric,
        results=[
            _result_schema(
                result,
                software_lookup,
                explanation=_tactic_scope_explanation(
                    filtered_input_techniques,
                    candidate_techniques_by_id.get(result.matched_entity_id, set()),
                    tactic_scope,
                ),
            )
            for result in results
        ],
    )


@router.post("/custom", response_model=ComparisonResponse)
def compare_custom_set(
    request: CustomComparisonRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> ComparisonResponse:
    """Compare an inline or saved custom TTP set against all actors."""
    return compare_custom_techniques(request, session, settings_store)


def compare_custom_techniques(
    request: CustomComparisonRequest | IncidentAnalysisRequest,
    session: Session,
    settings_store: SettingsStore,
) -> ComparisonResponse:
    """Compare an inline custom or incident TTP set against all actors."""
    settings = settings_store.load()
    active_source = settings.active_source
    input_id: str | None = None
    input_name = _input_name(request)

    if isinstance(request, CustomComparisonRequest) and request.custom_set_id is not None:
        custom_set = session.get(entities.CustomTTPSet, request.custom_set_id)
        if custom_set is None:
            raise AppError("Custom TTP set not found", status_code=404)
        input_id = custom_set.id
        input_name = custom_set.name
        input_techniques = set(custom_set.technique_ids)
    elif request.technique_ids is not None:
        technique_ids = _normalize_technique_ids(request.technique_ids)
        _validate_technique_ids(session, technique_ids)
        input_techniques = set(technique_ids)
    else:
        raise AppError("Provide either custom_set_id or technique_ids", status_code=422)

    technique_tactics = _technique_tactics(session)
    tactic_scope = _normalize_tactic_scope(request.tactics)
    candidates = _actor_candidates(session, active_source)
    if isinstance(request, CustomComparisonRequest) and request.target_ids is not None:
        candidates = _target_actor_candidates(candidates, request.target_ids)
    filtered_input_techniques = _filter_techniques_by_tactics(input_techniques, technique_tactics, tactic_scope)
    scoped_input_software = _software_for_tactic_scope(set(), filtered_input_techniques, tactic_scope)
    candidates = [_filter_entity_by_tactics(candidate, technique_tactics, tactic_scope) for candidate in candidates]
    candidate_techniques_by_id = {candidate.id: candidate.techniques for candidate in candidates}
    results = compare_against_entities(
        filtered_input_techniques,
        candidates,
        metric=request.metric,
        top_n=request.top_n,
        technique_tactics=technique_tactics,
        tactic_weights=settings.scoring.tactic_weights,
        input_software=scoped_input_software,
        technique_score_weight=settings.scoring.technique_score_weight,
        software_score_weight=settings.scoring.software_score_weight,
    )
    software_lookup = _software_lookup(session)
    return ComparisonResponse(
        input_id=input_id,
        input_name=input_name,
        input_type="incident" if isinstance(request, IncidentAnalysisRequest) else "custom_set",
        metric=request.metric,
        results=[
            _result_schema(
                result,
                software_lookup,
                explanation=_tactic_scope_explanation(
                    filtered_input_techniques,
                    candidate_techniques_by_id.get(result.matched_entity_id, set()),
                    tactic_scope,
                ),
            )
            for result in results
        ],
    )


def _input_name(request: CustomComparisonRequest | IncidentAnalysisRequest) -> str:
    """Return the display name for a custom comparison-like request."""
    if isinstance(request, IncidentAnalysisRequest):
        return request.incident_name
    return request.name or "Custom TTP Set"


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


def _target_actor_candidates(candidates: list[EntityTechniqueSet], target_ids: list[str]) -> list[EntityTechniqueSet]:
    """Filter actor candidates to an explicit selected target list."""
    requested_ids = list(dict.fromkeys(target_ids))
    if not requested_ids:
        raise AppError("Target actor list must include at least one actor", status_code=422)

    candidates_by_id = {candidate.id: candidate for candidate in candidates}
    missing_ids = sorted(set(requested_ids) - set(candidates_by_id))
    if missing_ids:
        raise AppError("Unknown target actor IDs", status_code=422, detail={"target_ids": missing_ids})

    return [candidates_by_id[target_id] for target_id in requested_ids]


def _actor_entity(actor: entities.Actor) -> EntityTechniqueSet:
    """Convert an actor ORM row to a comparable analytics entity."""
    return EntityTechniqueSet(
        id=actor.id,
        name=actor.name,
        source=actor.source,
        techniques=_technique_ids(actor.techniques),
        software=set(actor.software_used),
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


def _normalize_technique_ids(technique_ids: list[str]) -> list[str]:
    """Normalize user-provided technique IDs before validation and comparison."""
    return sorted({technique_id.strip().upper() for technique_id in technique_ids if technique_id.strip()})


def _technique_tactics(session: Session) -> dict[str, str]:
    """Return local technique-to-tactic metadata for scoring explanations."""
    rows = session.execute(select(entities.Technique.technique_id, entities.Technique.tactic)).all()
    return {technique_id: tactic for technique_id, tactic in rows}


def _normalize_tactic_scope(tactics: list[str] | None) -> set[str] | None:
    """Normalize optional tactic filters from API requests."""
    if tactics is None:
        return None

    normalized = {tactic.strip().lower() for tactic in tactics if tactic.strip()}
    if not normalized:
        raise AppError("Tactic scope must include at least one tactic", status_code=422)
    return normalized


def _filter_entity_by_tactics(
    entity: EntityTechniqueSet,
    technique_tactics: dict[str, str],
    tactic_scope: set[str] | None,
) -> EntityTechniqueSet:
    """Return a comparable entity with techniques constrained to selected tactics."""
    if tactic_scope is None:
        return entity

    filtered_techniques = _filter_techniques_by_tactics(entity.techniques, technique_tactics, tactic_scope)
    return EntityTechniqueSet(
        id=entity.id,
        name=entity.name,
        source=entity.source,
        techniques=filtered_techniques,
        software=_software_for_tactic_scope(entity.software, filtered_techniques, tactic_scope),
    )


def _software_for_tactic_scope(
    software_ids: set[str],
    filtered_techniques: set[str],
    tactic_scope: set[str] | None,
) -> set[str]:
    """Keep software evidence only when tactic-scoped technique evidence remains."""
    if tactic_scope is None or filtered_techniques:
        return software_ids
    return set()


def _filter_techniques_by_tactics(
    technique_ids: set[str],
    technique_tactics: dict[str, str],
    tactic_scope: set[str] | None,
) -> set[str]:
    """Keep only techniques whose metadata includes one selected tactic."""
    if tactic_scope is None:
        return technique_ids

    return {
        technique_id
        for technique_id in technique_ids
        if _technique_has_tactic(technique_tactics.get(technique_id, ""), tactic_scope)
    }


def _technique_has_tactic(tactic_value: str, tactic_scope: set[str]) -> bool:
    """Match single or comma-separated tactic values against the selected scope."""
    tactics = {item.strip().lower() for item in tactic_value.split(",") if item.strip()}
    return bool(tactics & tactic_scope)


def _tactic_scope_explanation(
    filtered_input_techniques: set[str],
    filtered_candidate_techniques: set[str],
    tactic_scope: set[str] | None,
) -> str | None:
    """Explain zero-evidence comparisons caused by tactic-scoped filtering."""
    if tactic_scope is None:
        return None

    if filtered_input_techniques and filtered_candidate_techniques:
        return None

    scope_label = ", ".join(sorted(tactic_scope))
    if not filtered_input_techniques and not filtered_candidate_techniques:
        return f"No source or matched entity techniques remain after applying tactic scope: {scope_label}."
    if not filtered_input_techniques:
        return f"No source techniques remain after applying tactic scope: {scope_label}."
    return f"No matched entity techniques remain after applying tactic scope: {scope_label}."


def _software_lookup(session: Session) -> dict[str, SoftwareSummary]:
    """Return software details keyed by internal software ID."""
    rows = session.scalars(select(entities.Software)).all()
    return {
        row.id: SoftwareSummary(
            id=row.id,
            name=row.name,
            software_type=cast(Literal["malware", "tool"], row.software_type),
        )
        for row in rows
        if row.software_type in {"malware", "tool"}
    }


def _rarity_weights_for_direct_comparison(
    candidates: list[EntityTechniqueSet],
    metric: str,
) -> dict[str, float]:
    """Return rarity weights for direct comparisons when the weighted metric is requested."""
    if metric != "jaccard_weighted":
        return {}

    from app.analytics.similarity import rarity_weights

    return rarity_weights([candidate.techniques for candidate in candidates])


def _result_schema(
    result: AnalyticsComparisonResult,
    software_lookup: dict[str, SoftwareSummary],
    explanation: str | None = None,
) -> ComparisonResult:
    """Convert an analytics result dataclass into the API response schema."""
    return ComparisonResult(
        matched_entity_id=result.matched_entity_id,
        matched_entity_name=result.matched_entity_name,
        matched_entity_source=result.matched_entity_source,
        score=result.score,
        technique_score=result.technique_score,
        software_score=result.software_score,
        technique_score_contribution=result.technique_score_contribution,
        software_score_contribution=result.software_score_contribution,
        shared_techniques=result.shared_techniques,
        unique_to_input=result.unique_to_input,
        unique_to_matched_entity=result.unique_to_matched_entity,
        shared_software=_software_items(result.shared_software, software_lookup),
        unique_to_input_software=_software_items(result.unique_to_input_software, software_lookup),
        unique_to_matched_entity_software=_software_items(result.unique_to_matched_entity_software, software_lookup),
        tactic_breakdown=[
            TacticBreakdown(
                tactic=item.tactic,
                shared_techniques=item.shared_techniques,
                input_technique_count=item.input_technique_count,
                matched_technique_count=item.matched_technique_count,
                shared_technique_count=item.shared_technique_count,
                union_technique_count=item.union_technique_count,
                score_contribution=item.score_contribution,
            )
            for item in result.tactic_breakdown
        ],
        rare_shared_techniques=result.rare_shared_techniques,
        explanation=explanation,
    )


def _software_items(software_ids: list[str], software_lookup: dict[str, SoftwareSummary]) -> list[SoftwareSummary]:
    """Resolve software IDs in stable display order, skipping missing stale IDs."""
    return sorted(
        [software_lookup[software_id] for software_id in software_ids if software_id in software_lookup],
        key=lambda item: item.name.lower(),
    )
