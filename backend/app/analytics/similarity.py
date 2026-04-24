"""Similarity metrics and explainability helpers for TTP sets."""

from __future__ import annotations

from dataclasses import dataclass
from math import log


@dataclass(frozen=True)
class SimilarityExplanation:
    """Set overlap details used to explain a comparison score."""

    shared_techniques: list[str]
    unique_to_input: list[str]
    unique_to_matched_entity: list[str]


def jaccard_similarity(input_techniques: set[str], matched_techniques: set[str]) -> float:
    """Return baseline Jaccard similarity normalized between 0 and 1.

    Empty-to-empty comparisons return 0.0 because no observed TTP evidence
    exists to support a meaningful similarity claim.
    """
    union = input_techniques | matched_techniques
    if not union:
        return 0.0
    return len(input_techniques & matched_techniques) / len(union)


def weighted_jaccard_similarity(
    input_techniques: set[str],
    matched_techniques: set[str],
    weights: dict[str, float],
) -> float:
    """Return rarity-weighted Jaccard similarity normalized between 0 and 1."""
    union = input_techniques | matched_techniques
    if not union:
        return 0.0

    shared_weight = sum(weights.get(technique_id, 1.0) for technique_id in input_techniques & matched_techniques)
    union_weight = sum(weights.get(technique_id, 1.0) for technique_id in union)
    if union_weight == 0:
        return 0.0
    return shared_weight / union_weight


def rarity_weights(actor_technique_sets: list[set[str]]) -> dict[str, float]:
    """Calculate ATT&CK technique rarity weights from actor usage counts."""
    counts: dict[str, int] = {}
    for technique_set in actor_technique_sets:
        for technique_id in technique_set:
            counts[technique_id] = counts.get(technique_id, 0) + 1

    # The spec's rarity weight is 1 / log(1 + count). A count of 1 gives the
    # highest weight, while techniques seen across many actors contribute less.
    return {technique_id: 1 / log(1 + count) for technique_id, count in counts.items()}


def explain_overlap(input_techniques: set[str], matched_techniques: set[str]) -> SimilarityExplanation:
    """Return sorted overlap and difference lists for comparison explainability."""
    return SimilarityExplanation(
        shared_techniques=sorted(input_techniques & matched_techniques),
        unique_to_input=sorted(input_techniques - matched_techniques),
        unique_to_matched_entity=sorted(matched_techniques - input_techniques),
    )
