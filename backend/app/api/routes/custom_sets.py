"""Minimal custom TTP set persistence endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.errors import AppError
from app.models import entities
from app.models.schemas import CustomTTPSet, CustomTTPSetCreate

router = APIRouter()


@router.post("", response_model=CustomTTPSet, status_code=status.HTTP_201_CREATED)
def create_custom_set(
    request: CustomTTPSetCreate,
    session: Annotated[Session, Depends(get_db_session)],
) -> entities.CustomTTPSet:
    """Save a custom TTP set for later comparison."""
    technique_ids = _normalize_technique_ids(request.technique_ids)
    _validate_technique_ids(session, technique_ids)
    custom_set = entities.CustomTTPSet(
        name=request.name,
        description=request.description,
        technique_ids=technique_ids,
        target_sectors=_normalize_tags(request.target_sectors),
        target_countries=_normalize_tags(request.target_countries),
        cves_exploited=_normalize_tags(request.cves_exploited),
        motivation=request.motivation.strip() if request.motivation else None,
    )
    session.add(custom_set)
    session.commit()
    session.refresh(custom_set)
    return custom_set


@router.get("", response_model=list[CustomTTPSet])
def list_custom_sets(session: Annotated[Session, Depends(get_db_session)]) -> list[entities.CustomTTPSet]:
    """List saved custom TTP sets."""
    return list(session.scalars(select(entities.CustomTTPSet).order_by(entities.CustomTTPSet.name)).all())


@router.get("/{custom_set_id}", response_model=CustomTTPSet)
def get_custom_set(
    custom_set_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> entities.CustomTTPSet:
    """Return a saved custom TTP set."""
    custom_set = session.get(entities.CustomTTPSet, custom_set_id)
    if custom_set is None:
        raise AppError("Custom TTP set not found", status_code=404)
    return custom_set


@router.put("/{custom_set_id}", response_model=CustomTTPSet)
def update_custom_set(
    custom_set_id: str,
    request: CustomTTPSetCreate,
    session: Annotated[Session, Depends(get_db_session)],
) -> entities.CustomTTPSet:
    """Update a saved custom TTP set in place."""
    custom_set = session.get(entities.CustomTTPSet, custom_set_id)
    if custom_set is None:
        raise AppError("Custom TTP set not found", status_code=404)

    technique_ids = _normalize_technique_ids(request.technique_ids)
    _validate_technique_ids(session, technique_ids)
    custom_set.name = request.name
    custom_set.description = request.description
    custom_set.technique_ids = technique_ids
    custom_set.target_sectors = _normalize_tags(request.target_sectors)
    custom_set.target_countries = _normalize_tags(request.target_countries)
    custom_set.cves_exploited = _normalize_tags(request.cves_exploited)
    custom_set.motivation = request.motivation.strip() if request.motivation else None
    session.add(custom_set)
    session.commit()
    session.refresh(custom_set)
    return custom_set


@router.delete("/{custom_set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_custom_set(
    custom_set_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> None:
    """Delete a saved custom TTP set."""
    custom_set = session.get(entities.CustomTTPSet, custom_set_id)
    if custom_set is None:
        raise AppError("Custom TTP set not found", status_code=404)

    session.delete(custom_set)
    session.commit()
    return None


def _validate_technique_ids(session: Session, technique_ids: list[str]) -> None:
    """Ensure every custom-set technique ID exists in the local technique table."""
    if not technique_ids:
        raise AppError("Custom TTP set must include at least one technique", status_code=422)

    existing_ids = set(
        session.scalars(select(entities.Technique.technique_id).where(entities.Technique.technique_id.in_(technique_ids)))
    )
    invalid_ids = sorted(set(technique_ids) - existing_ids)
    if invalid_ids:
        raise AppError("Unknown technique IDs", status_code=422, detail={"technique_ids": invalid_ids})


def _normalize_technique_ids(technique_ids: list[str]) -> list[str]:
    """Normalize user-provided technique IDs before validation and persistence."""
    return sorted({technique_id.strip().upper() for technique_id in technique_ids if technique_id.strip()})


def _normalize_tags(tags: list[str]) -> list[str]:
    """Deduplicate and strip whitespace from a list of string tags."""
    seen: set[str] = set()
    result: list[str] = []
    for tag in tags:
        t = tag.strip()
        if t and t not in seen:
            seen.add(t)
            result.append(t)
    return result
