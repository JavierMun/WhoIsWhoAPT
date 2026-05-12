"""Similarity metrics and explainability helpers for TTP sets."""

from __future__ import annotations

from dataclasses import dataclass
from math import log

DEFAULT_TACTIC_WEIGHT = 1.0


@dataclass(frozen=True)
class SimilarityExplanation:
    """Set overlap details used to explain a comparison score."""

    shared_techniques: list[str]
    unique_to_input: list[str]
    unique_to_matched_entity: list[str]


@dataclass(frozen=True)
class TacticBreakdown:
    """Per-tactic overlap and contribution details for a comparison score."""

    tactic: str
    shared_techniques: list[str]
    input_technique_count: int
    matched_technique_count: int
    shared_technique_count: int
    union_technique_count: int
    score_contribution: float


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


def tactic_weighted_jaccard_similarity(
    input_techniques: set[str],
    matched_techniques: set[str],
    technique_tactics: dict[str, str],
    tactic_weights: dict[str, float],
) -> float:
    """Return tactic-weighted Jaccard similarity normalized between 0 and 1."""
    weights = _tactic_weights_for_techniques(input_techniques | matched_techniques, technique_tactics, tactic_weights)
    return weighted_jaccard_similarity(input_techniques, matched_techniques, weights)


def blended_similarity(
    technique_score: float,
    software_score: float,
    technique_weight: float,
    software_weight: float,
    *,
    include_software: bool,
) -> tuple[float, float, float]:
    """Blend normalized technique and software scores into one normalized score.

    Software evidence is sparse in ATT&CK, so callers can disable the software
    component for a pair when either side has no software relationships.
    """
    safe_technique_weight = max(0.0, technique_weight)
    safe_software_weight = max(0.0, software_weight) if include_software else 0.0
    total_weight = safe_technique_weight + safe_software_weight
    if total_weight == 0:
        return 0.0, 0.0, 0.0

    technique_contribution = max(0.0, min(1.0, technique_score)) * safe_technique_weight / total_weight
    software_contribution = max(0.0, min(1.0, software_score)) * safe_software_weight / total_weight
    return (
        max(0.0, min(1.0, technique_contribution + software_contribution)),
        technique_contribution,
        software_contribution,
    )


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


def tactic_breakdown(
    input_techniques: set[str],
    matched_techniques: set[str],
    technique_tactics: dict[str, str],
    technique_weights: dict[str, float] | None = None,
) -> list[TacticBreakdown]:
    """Group overlap by tactic and show each tactic's share of the final score.

    The contribution is the weighted shared numerator for that tactic divided by
    the full weighted union denominator, so contributions sum to the score.
    """
    union = input_techniques | matched_techniques
    if not union:
        return []

    weights = technique_weights or {}
    union_weight = sum(weights.get(technique_id, DEFAULT_TACTIC_WEIGHT) for technique_id in union)
    if union_weight == 0:
        union_weight = DEFAULT_TACTIC_WEIGHT

    tactics = sorted({_primary_tactic_for(technique_id, technique_tactics) for technique_id in union})
    breakdown: list[TacticBreakdown] = []
    for tactic in tactics:
        input_for_tactic = {
            technique_id
            for technique_id in input_techniques
            if _primary_tactic_for(technique_id, technique_tactics) == tactic
        }
        matched_for_tactic = {
            technique_id
            for technique_id in matched_techniques
            if _primary_tactic_for(technique_id, technique_tactics) == tactic
        }
        union_for_tactic = input_for_tactic | matched_for_tactic
        shared_for_tactic = input_for_tactic & matched_for_tactic
        shared_weight = sum(weights.get(technique_id, DEFAULT_TACTIC_WEIGHT) for technique_id in shared_for_tactic)

        breakdown.append(
            TacticBreakdown(
                tactic=tactic,
                shared_techniques=sorted(shared_for_tactic),
                input_technique_count=len(input_for_tactic),
                matched_technique_count=len(matched_for_tactic),
                shared_technique_count=len(shared_for_tactic),
                union_technique_count=len(union_for_tactic),
                score_contribution=max(0.0, min(1.0, shared_weight / union_weight)),
            )
        )

    return breakdown


def _tactic_weights_for_techniques(
    technique_ids: set[str],
    technique_tactics: dict[str, str],
    tactic_weights: dict[str, float],
) -> dict[str, float]:
    """Map each technique to its configured tactic weight for weighted scoring."""
    return {
        technique_id: _weight_for_tactic_value(_tactic_for(technique_id, technique_tactics), tactic_weights)
        for technique_id in technique_ids
    }


def _tactic_for(technique_id: str, technique_tactics: dict[str, str]) -> str:
    """Return the full tactic value for a technique (may be comma-separated)."""
    return technique_tactics.get(technique_id) or "unknown"


def _primary_tactic_for(technique_id: str, technique_tactics: dict[str, str]) -> str:
    """Return the first individual tactic for grouping in breakdown displays.

    Uses only the first comma-separated value so each technique belongs to
    exactly one tactic bucket and shared counts sum correctly.
    """
    raw = technique_tactics.get(technique_id) or "unknown"
    first = raw.split(",")[0].strip()
    return first if first else "unknown"


def _weight_for_tactic_value(tactic_value: str, tactic_weights: dict[str, float]) -> float:
    """Return the strongest configured weight for single or comma-separated tactics."""
    tactics = [item.strip() for item in tactic_value.split(",") if item.strip()]
    if not tactics:
        return DEFAULT_TACTIC_WEIGHT
    return max(max(0.0, tactic_weights.get(tactic, DEFAULT_TACTIC_WEIGHT)) for tactic in tactics)
