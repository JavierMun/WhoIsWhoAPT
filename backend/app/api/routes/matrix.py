"""Actor similarity matrix API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analytics.comparison import EntityTechniqueSet
from app.analytics.matrix import ActorSimilarityMatrix, compute_actor_similarity_matrix
from app.database import get_db_session
from app.dependencies import get_settings_store
from app.errors import AppError
from app.models import entities
from app.models.schemas import MatrixActor, MatrixMetadata, MatrixRequest, MatrixResponse
from app.settings_store import SettingsStore

router = APIRouter()

_latest_matrix: ActorSimilarityMatrix | None = None


def get_latest_matrix() -> ActorSimilarityMatrix | None:
    """Return the latest in-process matrix result, if one exists."""
    return _latest_matrix


def set_latest_matrix(matrix: ActorSimilarityMatrix | None) -> None:
    """Store the latest in-process matrix result."""
    global _latest_matrix  # noqa: PLW0603 - intentional small in-process cache for synchronous MVP.

    _latest_matrix = matrix


@router.post("", response_model=MatrixResponse)
def compute_matrix(
    request: MatrixRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings_store: Annotated[SettingsStore, Depends(get_settings_store)],
) -> MatrixResponse:
    """Synchronously compute and store the latest all-vs-all actor matrix."""
    settings = settings_store.load()
    actors = _actor_candidates(session, settings.active_source)
    set_latest_matrix(
        compute_actor_similarity_matrix(
            actors,
            source=settings.active_source,
            metric=request.metric,
            technique_tactics=_technique_tactics(session),
            tactic_weights=settings.scoring.tactic_weights,
            technique_score_weight=settings.scoring.technique_score_weight,
            software_score_weight=settings.scoring.software_score_weight,
        )
    )
    latest_matrix = get_latest_matrix()
    if latest_matrix is None:
        raise AppError("Matrix has not been computed yet", status_code=404)
    return _response_schema(latest_matrix)


@router.get("/result", response_model=MatrixResponse)
def get_matrix_result() -> MatrixResponse:
    """Return the latest computed actor matrix."""
    latest_matrix = get_latest_matrix()
    if latest_matrix is None:
        raise AppError("Matrix has not been computed yet", status_code=404)
    return _response_schema(latest_matrix)


def _actor_candidates(session: Session, source: str) -> list[EntityTechniqueSet]:
    """Load actor candidates for the active source."""
    rows = session.scalars(select(entities.Actor).where(entities.Actor.source == source)).all()
    return [
        EntityTechniqueSet(
            id=row.id,
            name=row.name,
            source=row.source,
            techniques={str(ref["technique_id"]) for ref in row.techniques if ref.get("technique_id")},
            software=set(row.software_used),
        )
        for row in rows
    ]


def _technique_tactics(session: Session) -> dict[str, str]:
    """Return local technique-to-tactic metadata for tactic-aware scoring."""
    rows = session.execute(select(entities.Technique.technique_id, entities.Technique.tactic)).all()
    return {technique_id: tactic for technique_id, tactic in rows}


def _response_schema(matrix: ActorSimilarityMatrix) -> MatrixResponse:
    """Convert the analytics dataclass to the public API schema."""
    return MatrixResponse(
        metadata=MatrixMetadata(
            source=matrix.metadata.source,
            metric=matrix.metadata.metric,
            generated_at=matrix.metadata.generated_at,
            actor_count=matrix.metadata.actor_count,
        ),
        actors=[MatrixActor(id=actor.id, name=actor.name, source=actor.source) for actor in matrix.actors],
        matrix=matrix.matrix,
    )
