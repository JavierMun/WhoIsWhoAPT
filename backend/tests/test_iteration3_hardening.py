"""Iteration 3 matrix and clustering hardening tests."""

from datetime import datetime, timezone

import pytest

from app.analytics.clustering import hierarchical_clusters
from app.analytics.comparison import EntityTechniqueSet, SimilarityMetric
from app.analytics.matrix import ActorSimilarityMatrix, MatrixActor, MatrixMetadata, compute_actor_similarity_matrix


@pytest.mark.parametrize(
    "metric",
    ["jaccard", "jaccard_weighted", "tactic_weighted_jaccard", "software_weighted_jaccard"],
)
def test_matrix_is_symmetric_and_normalized_for_all_metrics(metric: SimilarityMetric) -> None:
    """All matrix metrics should produce stable symmetric normalized values."""
    matrix = compute_actor_similarity_matrix(
        _actors(),
        source="mitre",
        metric=metric,
        technique_tactics={"T1001": "execution", "T1002": "persistence", "T1003": "execution"},
        tactic_weights={"persistence": 3.0, "execution": 1.0},
        technique_score_weight=0.5,
        software_score_weight=0.5,
    )

    assert len(matrix.matrix) == len(matrix.actors)
    for row_index, row in enumerate(matrix.matrix):
        assert len(row) == len(matrix.actors)
        for column_index, value in enumerate(row):
            assert 0 <= value <= 1
            assert value == matrix.matrix[column_index][row_index]


def test_clustering_handles_empty_matrix() -> None:
    """Empty datasets should produce an empty cluster result, not an error."""
    clusters = hierarchical_clusters(_matrix([]))

    assert clusters.actor_count == 0
    assert clusters.cluster_count == 0
    assert clusters.labels == []


def test_clustering_handles_single_actor_matrix() -> None:
    """A single actor should form one cluster with one label."""
    clusters = hierarchical_clusters(_matrix([("actor-a", "Alpha")]))

    assert clusters.actor_count == 1
    assert clusters.cluster_count == 1
    assert len(clusters.labels) == 1
    assert clusters.labels[0].actor_id == "actor-a"
    assert clusters.labels[0].cluster_id == 1


def test_clustering_labels_follow_matrix_metric() -> None:
    """Cluster responses should preserve the metric from the matrix they use."""
    matrix = compute_actor_similarity_matrix(_actors(), source="mitre", metric="tactic_weighted_jaccard")

    clusters = hierarchical_clusters(matrix, min_similarity=0.2)

    assert clusters.metric == "tactic_weighted_jaccard"
    assert clusters.actor_count == len(matrix.actors)
    assert {label.actor_id for label in clusters.labels} == {actor.id for actor in matrix.actors}


def _actors() -> list[EntityTechniqueSet]:
    return [
        EntityTechniqueSet("actor-a", "Alpha", "mitre", {"T1001", "T1002"}, {"software-shared", "software-alpha"}),
        EntityTechniqueSet("actor-b", "Beta", "mitre", {"T1002", "T1003"}, {"software-shared", "software-beta"}),
        EntityTechniqueSet("actor-c", "Gamma", "mitre", set(), set()),
    ]


def _matrix(actor_rows: list[tuple[str, str]]) -> ActorSimilarityMatrix:
    now = datetime.now(timezone.utc)  # noqa: UP017 - local dev still supports Python 3.10.
    return ActorSimilarityMatrix(
        metadata=MatrixMetadata(source="mitre", metric="jaccard", generated_at=now, actor_count=len(actor_rows)),
        actors=[MatrixActor(id=actor_id, name=name, source="mitre") for actor_id, name in actor_rows],
        matrix=[[1.0 if row == column else 0.0 for column in actor_rows] for row in actor_rows],
    )
