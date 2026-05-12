"""Comparison orchestration over normalized actor technique sets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.analytics.similarity import (
    TacticBreakdown,
    blended_similarity,
    explain_overlap,
    jaccard_similarity,
    rarity_weights,
    tactic_breakdown,
    tactic_weighted_jaccard_similarity,
    weighted_jaccard_similarity,
)

SimilarityMetric = Literal[
    "jaccard", "jaccard_weighted", "tactic_weighted_jaccard", "software_weighted_jaccard", "holistic"
]

# Default dimension weights for holistic scoring
HOLISTIC_WEIGHTS: dict[str, float] = {
    "techniques": 0.60,
    "sectors": 0.15,
    "countries": 0.10,
    "cves": 0.10,
    "motivation": 0.05,
}


@dataclass(frozen=True)
class EntityTechniqueSet:
    """Comparable entity with a normalized ATT&CK technique set."""

    id: str
    name: str
    source: str
    techniques: set[str]
    software: set[str]
    # Holistic scoring fields (populated on demand)
    sectors: frozenset[str] = frozenset()
    countries: frozenset[str] = frozenset()
    cves: frozenset[str] = frozenset()
    motivation: str | None = None


@dataclass(frozen=True)
class ComparisonResult:
    """Ranked comparison score and basic explanation."""

    matched_entity_id: str
    matched_entity_name: str
    matched_entity_source: str
    score: float
    technique_score: float
    software_score: float
    technique_score_contribution: float
    software_score_contribution: float
    shared_techniques: list[str]
    unique_to_input: list[str]
    unique_to_matched_entity: list[str]
    shared_software: list[str]
    unique_to_input_software: list[str]
    unique_to_matched_entity_software: list[str]
    tactic_breakdown: list[TacticBreakdown]
    rare_shared_techniques: list[str]


def compare_against_entities(
    input_techniques: set[str],
    candidates: list[EntityTechniqueSet],
    metric: SimilarityMetric = "jaccard",
    top_n: int | None = None,
    exclude_entity_id: str | None = None,
    technique_tactics: dict[str, str] | None = None,
    tactic_weights: dict[str, float] | None = None,
    input_software: set[str] | None = None,
    technique_score_weight: float = 0.75,
    software_score_weight: float = 0.25,
    input_sectors: frozenset[str] = frozenset(),
    input_countries: frozenset[str] = frozenset(),
    input_cves: frozenset[str] = frozenset(),
    input_motivation: str | None = None,
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
            input_software=input_software,
            technique_score_weight=technique_score_weight,
            software_score_weight=software_score_weight,
            input_sectors=input_sectors,
            input_countries=input_countries,
            input_cves=input_cves,
            input_motivation=input_motivation,
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
    input_software: set[str] | None = None,
    technique_score_weight: float = 0.75,
    software_score_weight: float = 0.25,
    # Holistic enrichment for source
    input_sectors: frozenset[str] = frozenset(),
    input_countries: frozenset[str] = frozenset(),
    input_cves: frozenset[str] = frozenset(),
    input_motivation: str | None = None,
) -> ComparisonResult:
    """Compare an input TTP set to one entity."""
    technique_tactics = technique_tactics or {}
    tactic_weights = tactic_weights or {}

    if metric == "holistic":
        score = _holistic_score(
            input_techniques,
            candidate,
            input_sectors,
            input_countries,
            input_cves,
            input_motivation,
        )
        technique_score = jaccard_similarity(input_techniques, candidate.techniques)
        software_score = jaccard_similarity(input_software or set(), candidate.software)
        technique_contribution = score
        software_contribution = 0.0
        contribution_weights: dict[str, float] = {}

    elif metric == "jaccard_weighted":
        technique_score = weighted_jaccard_similarity(input_techniques, candidate.techniques, weights or {})
        contribution_weights = weights or {}
    elif metric == "tactic_weighted_jaccard":
        technique_score = tactic_weighted_jaccard_similarity(
            input_techniques,
            candidate.techniques,
            technique_tactics,
            tactic_weights,
        )
        contribution_weights = {
            technique_id: _tactic_contribution_weight(technique_tactics.get(technique_id, "unknown"), tactic_weights)
            for technique_id in input_techniques | candidate.techniques
        }
    else:
        technique_score = jaccard_similarity(input_techniques, candidate.techniques)
        contribution_weights = {}

    input_software = input_software or set()
    software_score = jaccard_similarity(input_software, candidate.software)
    if metric == "software_weighted_jaccard":
        # Software relationships are optional ATT&CK evidence. Blend them only
        # when both sides have observations so missing software does not reduce
        # otherwise valid TTP-only comparisons.
        score, technique_contribution, software_contribution = blended_similarity(
            technique_score,
            software_score,
            technique_score_weight,
            software_score_weight,
            include_software=bool(input_software and candidate.software),
        )
    else:
        score = technique_score
        technique_contribution = technique_score
        software_contribution = 0.0

    explanation = explain_overlap(input_techniques, candidate.techniques)
    software_explanation = explain_overlap(input_software, candidate.software)
    rare_shared_techniques = _rare_shared_techniques(explanation.shared_techniques, weights or {})
    return ComparisonResult(
        matched_entity_id=candidate.id,
        matched_entity_name=candidate.name,
        matched_entity_source=candidate.source,
        score=max(0.0, min(1.0, score)),
        technique_score=max(0.0, min(1.0, technique_score)),
        software_score=max(0.0, min(1.0, software_score)),
        technique_score_contribution=max(0.0, min(1.0, technique_contribution)),
        software_score_contribution=max(0.0, min(1.0, software_contribution)),
        shared_techniques=explanation.shared_techniques,
        unique_to_input=explanation.unique_to_input,
        unique_to_matched_entity=explanation.unique_to_matched_entity,
        shared_software=software_explanation.shared_techniques,
        unique_to_input_software=software_explanation.unique_to_input,
        unique_to_matched_entity_software=software_explanation.unique_to_matched_entity,
        tactic_breakdown=tactic_breakdown(
            input_techniques,
            candidate.techniques,
            technique_tactics,
            contribution_weights,
        ),
        rare_shared_techniques=rare_shared_techniques,
    )


def _holistic_score(
    input_techniques: set[str],
    candidate: EntityTechniqueSet,
    input_sectors: frozenset[str],
    input_countries: frozenset[str],
    input_cves: frozenset[str],
    input_motivation: str | None,
) -> float:
    """Multi-dimensional similarity combining techniques, sectors, countries, CVEs and motivation.

    Each dimension is included only when at least one side has data for it.
    If both sides lack data for a dimension it is excluded from the weighted average
    (so MITRE-only actors are not penalized for missing enrichment).
    """

    def _jaccard(a: frozenset[str] | set[str], b: frozenset[str] | set[str]) -> float:
        union = a | b
        if not union:
            return 0.0
        return len(a & b) / len(union)

    active: dict[str, float] = {}  # dimension → score

    # Techniques: always active
    active["techniques"] = _jaccard(input_techniques, candidate.techniques)

    # Sectors
    if input_sectors or candidate.sectors:
        active["sectors"] = _jaccard(input_sectors, candidate.sectors)

    # Countries
    if input_countries or candidate.countries:
        active["countries"] = _jaccard(input_countries, candidate.countries)

    # CVEs
    if input_cves or candidate.cves:
        active["cves"] = _jaccard(input_cves, candidate.cves)

    # Motivation
    if input_motivation is not None or candidate.motivation is not None:
        if input_motivation and candidate.motivation:
            active["motivation"] = 1.0 if input_motivation.lower() == candidate.motivation.lower() else 0.0
        else:
            active["motivation"] = 0.0

    # Renormalize weights to active dimensions
    total_weight = sum(HOLISTIC_WEIGHTS[d] for d in active)
    if total_weight == 0:
        return 0.0

    return sum(active[d] * HOLISTIC_WEIGHTS[d] for d in active) / total_weight


def _tactic_contribution_weight(tactic_value: str, tactic_weights: dict[str, float]) -> float:
    """Return the strongest configured tactic weight for contribution display."""
    tactics = [item.strip() for item in tactic_value.split(",") if item.strip()]
    if not tactics:
        return 1.0
    return max(max(0.0, tactic_weights.get(tactic, 1.0)) for tactic in tactics)


def _rare_shared_techniques(shared_techniques: list[str], weights: dict[str, float]) -> list[str]:
    """Return shared techniques whose rarity weight is above the default unweighted value."""
    return [
        technique_id
        for technique_id in sorted(shared_techniques, key=lambda item: (-weights.get(item, 1.0), item))
        if weights.get(technique_id, 1.0) > 1.0
    ]
