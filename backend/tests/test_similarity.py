"""Similarity metric edge-case tests."""

from app.analytics.similarity import (
    blended_similarity,
    jaccard_similarity,
    tactic_breakdown,
    tactic_weighted_jaccard_similarity,
    weighted_jaccard_similarity,
)


def test_jaccard_identical_sets() -> None:
    """Identical non-empty sets should score 1.0."""
    assert jaccard_similarity({"T1001", "T1002"}, {"T1001", "T1002"}) == 1.0


def test_jaccard_disjoint_sets() -> None:
    """Disjoint sets should score 0.0."""
    assert jaccard_similarity({"T1001"}, {"T1002"}) == 0.0


def test_jaccard_partial_overlap() -> None:
    """Partial overlap should divide shared techniques by the union."""
    assert jaccard_similarity({"T1001", "T1002"}, {"T1002", "T1003"}) == 1 / 3


def test_jaccard_empty_sets() -> None:
    """Empty comparisons should not imply a perfect match."""
    assert jaccard_similarity(set(), set()) == 0.0
    assert jaccard_similarity({"T1001"}, set()) == 0.0


def test_weighted_jaccard_partial_overlap() -> None:
    """Weighted Jaccard should use weighted intersection over weighted union."""
    score = weighted_jaccard_similarity(
        {"T1001", "T1002"},
        {"T1002", "T1003"},
        {"T1001": 2.0, "T1002": 3.0, "T1003": 5.0},
    )

    assert score == 0.3


def test_tactic_weighted_jaccard_uses_configured_tactic_weights() -> None:
    """Tactic-weighted Jaccard should emphasize overlap in configured tactics."""
    score = tactic_weighted_jaccard_similarity(
        {"T1001", "T1002"},
        {"T1002", "T1003"},
        {"T1001": "execution", "T1002": "persistence", "T1003": "execution"},
        {"persistence": 3.0, "execution": 1.0},
    )

    assert score == 3 / 5


def test_tactic_weighted_jaccard_handles_multi_tactic_values() -> None:
    """Configured secondary tactics should still influence weighted scoring."""
    score = tactic_weighted_jaccard_similarity(
        {"T1001", "T1002"},
        {"T1002", "T1003"},
        {"T1001": "execution", "T1002": "execution, persistence", "T1003": "execution"},
        {"persistence": 3.0, "execution": 1.0},
    )

    assert score == 3 / 5


def test_tactic_breakdown_groups_shared_techniques_and_contributions() -> None:
    """Breakdown should group shared techniques by tactic and sum to the score."""
    breakdown = tactic_breakdown(
        {"T1001", "T1002"},
        {"T1002", "T1003"},
        {"T1001": "execution", "T1002": "persistence", "T1003": "execution"},
        {"T1001": 1.0, "T1002": 3.0, "T1003": 1.0},
    )

    persistence = next(item for item in breakdown if item.tactic == "persistence")
    assert persistence.shared_techniques == ["T1002"]
    assert persistence.shared_technique_count == 1
    assert persistence.score_contribution == 3 / 5


def test_blended_similarity_ignores_software_when_not_applicable() -> None:
    """Software weighting should not penalize pairs without comparable software evidence."""
    score, technique_contribution, software_contribution = blended_similarity(
        technique_score=0.5,
        software_score=0.0,
        technique_weight=0.75,
        software_weight=0.25,
        include_software=False,
    )

    assert score == 0.5
    assert technique_contribution == 0.5
    assert software_contribution == 0.0
