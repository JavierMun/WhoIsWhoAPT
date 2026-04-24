"""Similarity metric edge-case tests."""

from app.analytics.similarity import jaccard_similarity, weighted_jaccard_similarity


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
