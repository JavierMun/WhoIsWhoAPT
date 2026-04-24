"""Technique lookup endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.models import entities
from app.models.schemas import TechniqueListItem

router = APIRouter()


@router.get("", response_model=list[TechniqueListItem])
def list_techniques(session: Annotated[Session, Depends(get_db_session)]) -> list[TechniqueListItem]:
    """List normalized ATT&CK techniques for custom TTP set creation."""
    rows = session.scalars(select(entities.Technique).order_by(entities.Technique.technique_id)).all()
    return [
        TechniqueListItem(
            technique_id=row.technique_id,
            name=row.name,
            tactic=row.tactic,
            is_subtechnique=row.is_subtechnique,
            parent_id=row.parent_id,
        )
        for row in rows
    ]
