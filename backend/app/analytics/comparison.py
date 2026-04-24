"""Comparison orchestration over normalized actor technique sets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.analytics.similarity import (
    TacticBreakdown,
    explain_overlap,
    jaccard_similarity,
    rarity_weights,
    tactic_breakdown,
    tactic_weighted_jaccard_similarity,
    weighted_jaccard_similarity,
)

SimilarityMetric = Literal["jaccard", "jaccard_weighted", "tactic_weighted_jaccard"]


@dataclass(frozen=True)
class EntityTechniqueSet:
    """Comparable entity with a normalized ATT&CK technique set."""

    id: str
    name: str
    source: str
    techniques: set[str]


@dataclass(frozen=True)
class ComparisonResult:
    """Ranked comparison score and basic explanation."""

    matched_entity_id: str
    matched_entity_name: str
    matched_entity_source: str
    score: float
    shared_techniques: list[str]
    unique_to_input: list[str]
    unique_to_matched_entity: list[str]
    tactic_breakdown: list[TacticBreakdown]


def compare_against_entities(
    input_techniques: set[str],
    candidates: list[EntityTechniqueSet],
    metric: SimilarityMetric = "jaccard",
    top_n: int | None = None,
    exclude_entity_id: str | None = None,
    technique_tactics: dict[str, str] | None = None,
    tactic_weights: dict[str, float] | None = None,
) -> list[ComparisonResult]:
    """Compare an input TTP set against candidate entities and rank results."""
    weights = rarity_weights([candidate.techniques for candidate in candidates]) if metric == "jaccard_weighted" else {}
    results = [
        compare_pair(
            input_techniques,
            candidate,
            metric=metric,
            weights=weights,
            technique_tactics=technique_tactics,
            tactic_weights=tactic_weights,
        )
        for candidate in candidates
        if candidate.id != exclude_entity_id
    ]
    results.sort(key=lambda result: (-result.score, result.matched_entity_name.lower()))
    return results[:top_n] if top_n is not None else results


def compare_pair(
    input_techniques: set[str],
    candidate: EntityTechniqueSet,
    metric: SimilarityMetric = "jaccard",
    weights: dict[str, float] | None = None,
    technique_tactics: dict[str, str] | None = None,
    tactic_weights: dict[str, float] | None = None,
) -> ComparisonResult:
    """Compare an input TTP set to one entity."""
    technique_tactics = technique_tactics or {}
    tactic_weights = tactic_weights or {}

    if metric == "jaccard_weighted":
        score = weighted_jaccard_similarity(input_techniques, candidate.techniques, weights or {})
        contribution_weights = weights or {}
    elif metric == "tactic_weighted_jaccard":
        score = tactic_weighted_jaccard_similarity(
            input_techniques,
            candidate.techniques,
            technique_tactics,
            tactic_weights,
        )
        contribution_weights = {
            technique_id: max(0.0, tactic_weights.get(technique_tactics.get(technique_id, "unknown"), 1.0))
            for technique_id in input_techniques | candidate.techniques
        }
    else:
        score = jaccard_similarity(input_techniques, candidate.techniques)
        contribution_weights = {}

    explanation = explain_overlap(input_techniques, candidate.techniques)
    return ComparisonResult(
        matched_entity_id=candidate.id,
        matched_entity_name=candidate.name,
        matched_entity_source=candidate.source,
        score=max(0.0, min(1.0, score)),
        shared_techniques=explanation.shared_techniques,
        unique_to_input=explanation.unique_to_input,
        unique_to_matched_entity=explanation.unique_to_matched_entity,
        tactic_breakdown=tactic_breakdown(
            input_techniques,
            candidate.techniques,
            technique_tactics,
            contribution_weights,
        ),
    )
