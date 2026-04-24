"""Clustering helpers for actor similarity matrices."""

from __future__ import annotations

from dataclasses import dataclass

from app.analytics.matrix import ActorSimilarityMatrix, MatrixActor


@dataclass(frozen=True)
class ActorClusterLabel:
    """Cluster assignment for one actor."""

    actor_id: str
    actor_name: str
    source: str
    cluster_id: int


@dataclass(frozen=True)
class ClusterResult:
    """Cluster labels derived from a similarity matrix."""

    source: str
    metric: str
    generated_at: str
    actor_count: int
    cluster_count: int
    min_similarity: float
    labels: list[ActorClusterLabel]


def hierarchical_clusters(matrix: ActorSimilarityMatrix, min_similarity: float = 0.15) -> ClusterResult:
    """Cluster actors with deterministic average-link hierarchical agglomeration."""
    safe_min_similarity = max(0.0, min(1.0, min_similarity))
    clusters = [{index} for index in range(len(matrix.actors))]

    while len(clusters) > 1:
        best_pair: tuple[int, int] | None = None
        best_similarity = -1.0

        for left_index in range(len(clusters)):
            for right_index in range(left_index + 1, len(clusters)):
                similarity = _average_link_similarity(clusters[left_index], clusters[right_index], matrix.matrix)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_pair = (left_index, right_index)

        if best_pair is None or best_similarity < safe_min_similarity:
            break

        left_index, right_index = best_pair
        clusters[left_index] = clusters[left_index] | clusters[right_index]
        del clusters[right_index]

    sorted_clusters = sorted(clusters, key=lambda cluster: _cluster_sort_key(cluster, matrix.actors))
    labels: list[ActorClusterLabel] = []
    for cluster_id, cluster in enumerate(sorted_clusters, start=1):
        for actor_index in sorted(cluster, key=lambda index: matrix.actors[index].name.lower()):
            actor = matrix.actors[actor_index]
            labels.append(
                ActorClusterLabel(
                    actor_id=actor.id,
                    actor_name=actor.name,
                    source=actor.source,
                    cluster_id=cluster_id,
                )
            )

    return ClusterResult(
        source=matrix.metadata.source,
        metric=matrix.metadata.metric,
        generated_at=matrix.metadata.generated_at.isoformat(),
        actor_count=matrix.metadata.actor_count,
        cluster_count=len(sorted_clusters),
        min_similarity=safe_min_similarity,
        labels=labels,
    )


def _average_link_similarity(left: set[int], right: set[int], values: list[list[float]]) -> float:
    """Return average pairwise similarity between two clusters."""
    pair_scores = [
        max(0.0, min(1.0, values[left_index][right_index]))
        for left_index in left
        for right_index in right
        if left_index < len(values) and right_index < len(values[left_index])
    ]
    if not pair_scores:
        return 0.0
    return sum(pair_scores) / len(pair_scores)


def _cluster_sort_key(cluster: set[int], actors: list[MatrixActor]) -> tuple[int, str]:
    """Sort larger clusters first, then by first actor name for stable labels."""
    actor_names = [actors[index].name.lower() for index in cluster]
    return (-len(cluster), min(actor_names, default=""))
