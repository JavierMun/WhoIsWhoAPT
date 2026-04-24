"""Cluster API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Query

from app.analytics.clustering import hierarchical_clusters
from app.api.routes.matrix import get_latest_matrix
from app.errors import AppError
from app.models.schemas import ClusterLabel, ClusterResponse

router = APIRouter()


@router.get("", response_model=ClusterResponse)
def get_clusters(
    min_similarity: Annotated[float, Query(ge=0, le=1)] = 0.15,
) -> ClusterResponse:
    """Return hierarchical cluster labels for the latest similarity matrix."""
    matrix = get_latest_matrix()
    if matrix is None:
        raise AppError("Matrix has not been computed yet", status_code=404)

    clusters = hierarchical_clusters(matrix, min_similarity=min_similarity)
    return ClusterResponse(
        source=clusters.source,
        metric=clusters.metric,
        generated_at=clusters.generated_at,
        actor_count=clusters.actor_count,
        cluster_count=clusters.cluster_count,
        min_similarity=clusters.min_similarity,
        labels=[
            ClusterLabel(
                actor_id=label.actor_id,
                actor_name=label.actor_name,
                source=label.source,
                cluster_id=label.cluster_id,
            )
            for label in clusters.labels
        ],
    )
