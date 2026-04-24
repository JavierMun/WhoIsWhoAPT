"""All-vs-all actor similarity matrix computation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.analytics.comparison import EntityTechniqueSet, SimilarityMetric, compare_pair
from app.analytics.similarity import rarity_weights


@dataclass(frozen=True)
class MatrixActor:
    """Actor metadata aligned with matrix row and column indexes."""

    id: str
    name: str
    source: str


@dataclass(frozen=True)
class MatrixMetadata:
    """Context for a generated actor similarity matrix."""

    source: str
    metric: SimilarityMetric
    generated_at: datetime
    actor_count: int


@dataclass(frozen=True)
class ActorSimilarityMatrix:
    """Frontend-friendly all-vs-all similarity matrix."""

    metadata: MatrixMetadata
    actors: list[MatrixActor]
    matrix: list[list[float]]


def compute_actor_similarity_matrix(
    actors: list[EntityTechniqueSet],
    source: str,
    metric: SimilarityMetric = "jaccard",
    technique_tactics: dict[str, str] | None = None,
    tactic_weights: dict[str, float] | None = None,
    technique_score_weight: float = 0.75,
    software_score_weight: float = 0.25,
) -> ActorSimilarityMatrix:
    """Compute a normalized pairwise similarity matrix for all actors."""
    ordered_actors = sorted(actors, key=lambda actor: actor.name.lower())
    weights = rarity_weights([actor.techniques for actor in ordered_actors]) if metric == "jaccard_weighted" else {}

    values: list[list[float]] = [[0.0 for _ in ordered_actors] for _ in ordered_actors]
    for input_index, input_actor in enumerate(ordered_actors):
        for matched_index, matched_actor in enumerate(ordered_actors):
            if matched_index < input_index:
                values[input_index][matched_index] = values[matched_index][input_index]
                continue
            result = compare_pair(
                input_actor.techniques,
                matched_actor,
                metric=metric,
                weights=weights,
                technique_tactics=technique_tactics,
                tactic_weights=tactic_weights,
                input_software=input_actor.software,
                technique_score_weight=technique_score_weight,
                software_score_weight=software_score_weight,
            )
            values[input_index][matched_index] = max(0.0, min(1.0, result.score))

    return ActorSimilarityMatrix(
        metadata=MatrixMetadata(
            source=source,
            metric=metric,
            generated_at=datetime.now(timezone.utc),  # noqa: UP017 - local dev still supports Python 3.10.
            actor_count=len(ordered_actors),
        ),
        actors=[MatrixActor(id=actor.id, name=actor.name, source=actor.source) for actor in ordered_actors],
        matrix=values,
    )
