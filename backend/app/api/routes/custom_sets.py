"""Minimal custom TTP set persistence endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.models import entities
from app.models.schemas import CustomTTPSet, CustomTTPSetCreate

router = APIRouter()


@router.post("", response_model=CustomTTPSet, status_code=status.HTTP_201_CREATED)
def create_custom_set(
    request: CustomTTPSetCreate,
    session: Annotated[Session, Depends(get_db_session)],
) -> entities.CustomTTPSet:
    """Save a custom TTP set for later comparison."""
    custom_set = entities.CustomTTPSet(
        name=request.name,
        description=request.description,
        technique_ids=sorted(set(request.technique_ids)),
    )
    session.add(custom_set)
    session.commit()
    session.refresh(custom_set)
    return custom_set


@router.get("", response_model=list[CustomTTPSet])
def list_custom_sets(session: Annotated[Session, Depends(get_db_session)]) -> list[entities.CustomTTPSet]:
    """List saved custom TTP sets."""
    return list(session.scalars(select(entities.CustomTTPSet).order_by(entities.CustomTTPSet.name)).all())
